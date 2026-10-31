"""
Tool-call guard used for the AgentDojo evaluation. No `agentdojo` imports, so it is unit-testable anywhere.

ToolGuard's own policy, risk and approval rules are written for MLflow / Docker tools and are NOT used here.
Two parts of GuardML do not depend on those tools and are reused unchanged:

  * provenance (toolguard.provenance): did an argument value come from the user's request, or only from
    untrusted tool output (emails, files, web pages, channel messages)?
  * the intent judge (toolguard.intent): given ONLY the user's request and the proposed call, did the user
    ask for this action?

Only state-changing (or outbound-network) tools are checked; reads pass. AgentDojo has no human in the loop,
so anything that GuardML would escalate to a human is treated as blocked here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from guardml.toolguard.intent import IntentJudge
from guardml.toolguard.provenance import MAX_UNTRUSTED_TOKENS, describe, find_untrusted_args, tokens

# Tools that change state or send data out, across the four AgentDojo suites. Everything else is a read.
# get_webpage (slack) is included: fetching an attacker-chosen URL is itself an injection goal.
WRITE_TOOLS = frozenset({
    # banking
    'send_money', 'schedule_transaction', 'update_scheduled_transaction', 'update_password', 'update_user_info',
    # workspace
    'add_calendar_event_participants', 'append_to_file', 'cancel_calendar_event', 'create_calendar_event',
    'create_file', 'delete_email', 'delete_file', 'reschedule_calendar_event', 'send_email', 'share_file',
    # travel
    'reserve_car_rental', 'reserve_hotel', 'reserve_restaurant',
    # slack
    'add_user_to_channel', 'invite_user_to_slack', 'remove_user_from_slack', 'send_channel_message',
    'send_direct_message', 'post_webpage', 'get_webpage',
})

# Provenance is checked only on arguments that name a DESTINATION or PRINCIPAL: who receives data or money,
# which URL is contacted, who gains access, which credential is set. Opaque ids (event_id, file_id, a
# transaction id), amounts, locations and free text are not checked: an agent has to read ids out of tool
# output to do its job, so flagging them only breaks normal tasks (the first version of this rule checked every
# identifier-like argument and blocked 58-90% of AgentDojo's legitimate ground-truth tasks that write; see README).
SINK_ARGS = frozenset({
    'recipient', 'recipients', 'participants', 'user', 'user_email', 'email', 'url', 'iban', 'password',
})


@dataclass
class Decision:
    allowed: bool
    rule: str      # read | ok | provenance | intent | intent_error
    reason: str = ''


class ToolCallGuard:
    """Stateless per call: pass the user's request and every tool output seen so far."""

    def __init__(self, provenance: bool = True, intent: bool = True, judge: Optional[IntentJudge] = None):
        if intent and judge is None:
            raise ValueError('intent=True needs an IntentJudge')
        self.provenance, self.intent, self.judge = provenance, intent, judge

    def check(self, user_query: str, tool_outputs: Iterable[Tuple[str, str]], tool: str,
              args: Dict[str, Any]) -> Decision:
        if tool not in WRITE_TOOLS:
            return Decision(True, 'read')

        if self.provenance:
            trusted = tokens(user_query)
            untrusted: Dict[str, str] = {}
            overflow = False
            for src, text in tool_outputs:
                for t in tokens(text):
                    if t not in untrusted:
                        untrusted[t] = src
                if len(untrusted) > MAX_UNTRUSTED_TOKENS:
                    overflow = True
                    break
            checked = {k: v for k, v in args.items() if k in SINK_ARGS}
            hits = find_untrusted_args(checked, trusted, untrusted, overflow)
            if hits:
                return Decision(False, 'provenance', describe(hits))

        if self.intent:
            res = self.judge.check([user_query], tool, args)
            if not res.aligned:
                return Decision(False, 'intent_error' if res.error else 'intent', res.rationale)

        return Decision(True, 'ok')


CONFIGS = {
    'none': None,                                        # baseline: no guard
    'provenance': dict(provenance=True, intent=False),
    'intent': dict(provenance=False, intent=True),
    'full': dict(provenance=True, intent=True),
}
