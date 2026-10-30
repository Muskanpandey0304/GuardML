import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv
load_dotenv()

import requests
import streamlit as st

API_BASE = os.getenv('GUARDML_API_URL', 'http://localhost:8000')

st.set_page_config(
    page_title='GuardML - Secure MLOps Agent',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded',
)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
for key, default in (
    ('messages', []),
    ('steps', []),
    ('current_session_id', None),
    ('api_token', ''),
    ('identity', None),   # {'name':..., 'role':..., 'environment':...} once logged in
    ('auth_notice', ''),
):
    if key not in st.session_state:
        st.session_state[key] = default

# ---------------------------------------------------------------------------
# API helpers: every call carries the user's bearer token
# ---------------------------------------------------------------------------
def _headers() -> Dict[str, str]:
    token = st.session_state.get('api_token', '')
    return {'Authorization': f'Bearer {token}'} if token else {}


def _clear_auth_if_rejected(resp: requests.Response) -> requests.Response:
    """If the API says our token is no longer valid, drop it so the login gate shows next run."""
    if resp.status_code == 401:
        st.session_state.api_token = ''
        st.session_state.identity = None
        st.session_state.auth_notice = 'Your session expired or the token was rejected. Please sign in again.'
    return resp


def api_get(path: str, timeout: int = 5) -> requests.Response:
    return _clear_auth_if_rejected(requests.get(f'{API_BASE}{path}', headers=_headers(), timeout=timeout))


def api_post(path: str, payload: Dict[str, Any], timeout: int = 15) -> requests.Response:
    return _clear_auth_if_rejected(
        requests.post(f'{API_BASE}{path}', json=payload, headers=_headers(), timeout=timeout)
    )


def error_detail(resp: requests.Response) -> str:
    try:
        return str(resp.json().get('detail', resp.text))
    except Exception:
        return resp.text or f'HTTP {resp.status_code}'


def try_login(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        r = requests.get(f'{API_BASE}/me', headers={'Authorization': f'Bearer {token}'}, timeout=5)
    except Exception as e:
        return None, f'Cannot reach GuardML API at {API_BASE}: {e}'
    if r.status_code == 200:
        return r.json(), None
    if r.status_code == 401:
        return None, 'Invalid token.'
    return None, f'Unexpected response from API ({r.status_code}).'


# Auto-login: if GUARDML_API_TOKEN is set in .env, skip the sign-in screen entirely.
_env_token = os.getenv('GUARDML_API_TOKEN', '').strip()
if _env_token and st.session_state.identity is None:
    _ident, _err = try_login(_env_token)
    if _ident:
        st.session_state.api_token = _env_token
        st.session_state.identity = _ident


def risk_badge(label: str) -> str:
    colors = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}
    return colors.get(label, '⚪')


def verdict_badge(verdict: str) -> str:
    badges = {'ALLOW': '✅', 'BLOCK': '🚫', 'NEEDS_APPROVAL': '⏳', 'APPROVED_EXECUTED': '✅', 'ROLLBACK': '↩️'}
    return badges.get(verdict, '❓')


# ---------------------------------------------------------------------------
# Sidebar + login gate
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title('🛡️ GuardML')
    st.caption('Secure MLOps Agent')
    st.divider()

    if st.session_state.identity is None:
        st.subheader('Sign in')
        if st.session_state.auth_notice:
            st.warning(st.session_state.auth_notice)
        with st.form('login_form'):
            token_input = st.text_input('API token', type='password')
            login_clicked = st.form_submit_button('Sign in')
        if login_clicked:
            if not token_input.strip():
                st.error('Enter your token.')
            else:
                ident, err = try_login(token_input.strip())
                if ident:
                    st.session_state.api_token = token_input.strip()
                    st.session_state.identity = ident
                    st.session_state.auth_notice = ''
                    st.rerun()
                else:
                    st.error(err)
    else:
        ident = st.session_state.identity
        st.markdown(f"**User:** `{ident['name']}`")
        st.markdown(f"**Role:** `{ident['role']}`")
        # Environment is decided by the server; the UI can only display it.
        env_label = ident.get('environment', '?')
        st.markdown(f"**Environment:** `{env_label}` {'🔴' if env_label == 'production' else '🟢'}")
        if st.button('Sign out'):
            st.session_state.api_token = ''
            st.session_state.identity = None
            st.session_state.messages = []
            st.session_state.steps = []
            st.session_state.current_session_id = None
            st.rerun()

    st.divider()
    st.subheader('About')
    st.markdown(
        'GuardML diagnoses model issues using a **guarded tool layer**.\n\n'
        'Every tool call is logged, risk-scored, and blocked/approved based on policy.'
    )

if st.session_state.identity is None:
    st.info('🔒 Please sign in with your API token (sidebar) to use GuardML.')
    st.stop()

identity = st.session_state.identity
is_approver = identity.get('role') == 'approver'


# ---------------------------------------------------------------------------
# Main tabs
# ---------------------------------------------------------------------------
tab_chat, tab_audit, tab_replay, tab_reports = st.tabs(['💬 Chat', '📋 Audit Log', '▶️ Replay', '📄 Reports'])

with tab_chat:
    col_chat, col_steps = st.columns([2, 1])

    with col_chat:
        st.subheader('Chat')
        for msg in st.session_state.messages:
            with st.chat_message(msg['role']):
                st.markdown(msg['content'])

        if prompt := st.chat_input('Ask GuardML to diagnose a problem...'):
            st.session_state.messages.append({'role': 'user', 'content': prompt})
            with st.chat_message('user'):
                st.markdown(prompt)

            st.session_state.steps = []

            with st.chat_message('assistant'):
                with st.spinner('Investigating...'):
                    try:
                        # The server picks the environment and the session id.
                        resp = api_post('/run', {'message': prompt})
                        if not resp.ok:
                            raise RuntimeError(f'{resp.status_code}: {error_detail(resp)}')
                        session_id = resp.json()['session_id']
                        st.session_state.current_session_id = session_id

                        max_wait = 180
                        waited = 0
                        answer = None
                        while waited < max_wait:
                            time.sleep(1)
                            waited += 1

                            poll = api_get(f'/session/{session_id}')
                            if poll.ok:
                                data = poll.json()
                                st.session_state.steps = data.get('steps', [])
                                if data.get('status') in ('done', 'error'):
                                    answer = data.get('answer', data.get('error', 'No answer'))
                                    break
                                # If any step requires approval, inform user and break so UI can render approval card
                                if any(s.get('verdict') == 'NEEDS_APPROVAL' for s in data.get('steps', [])):
                                    answer = "⚠️ **Action Paused**: This operation requires human approval. Please review the **Pending Approvals** panel on the right and have an approver click **Approve** or **Deny**."
                                    break
                            elif poll.status_code == 401:
                                raise RuntimeError('Session expired. Please sign in again.')
                        if answer is None:
                            answer = 'Processing request... Check the steps panel for live progress.'
                        st.markdown(answer)
                        st.session_state.messages.append({'role': 'assistant', 'content': answer})

                    except Exception as e:
                        error_msg = f'Error talking to GuardML API: {e}\n\nMake sure the API is running: `uvicorn guardml.api.main:app --reload`'
                        st.error(error_msg)
                        st.session_state.messages.append({'role': 'assistant', 'content': error_msg})

    with col_steps:
        st.subheader('Steps Taken')
        if st.session_state.steps:
            for i, step in enumerate(st.session_state.steps):
                tool = step.get('tool', step.get('type', '?'))
                verdict = step.get('verdict', '')
                risk = step.get('risk_label', '')
                score = step.get('risk_score', 0)
                with st.expander(f"{i+1}. {verdict_badge(verdict)} {tool} {risk_badge(risk)}", expanded=False):
                    st.markdown(f'**Verdict**: `{verdict}`')
                    st.markdown(f'**Risk**: {risk_badge(risk)} `{risk}` (score={score})')
                    if step.get('args'):
                        st.markdown('**Args**:')
                        st.json(step['args'])
                    if step.get('result'):
                        st.markdown('**Result**:')
                        result = step['result']
                        if isinstance(result, dict):
                            st.json(result)
                        else:
                            st.code(str(result)[:500])
                    if step.get('approval_id'):
                        st.warning(f'Approval required: `{step["approval_id"]}`')
        else:
            st.info('Steps will appear here as the agent works.')

        st.divider()
        st.subheader('Pending Approvals')
        if st.button('Refresh approvals'):
            pass
        try:
            approvals_resp = api_get('/approvals', timeout=3)
            if approvals_resp.ok:
                approvals = approvals_resp.json()
                if approvals:
                    for ap in approvals:
                        with st.container(border=True):
                            st.markdown(f"**Tool**: `{ap['tool_name']}`")
                            st.markdown(f"**Risk**: {risk_badge(ap.get('risk_label',''))} {ap.get('risk_label','')} (score={ap.get('risk_score',0)})")
                            if ap.get('env'):
                                st.markdown(f"**Environment**: `{ap['env']}`")
                            st.markdown(f"**Agent's reason**: {ap.get('llm_reason') or ap.get('reason','')}")
                            # Why ToolGuard stopped it: provenance, intent check, risk factors...
                            try:
                                guard_reasons = json.loads(ap.get('reasons') or '[]')
                            except ValueError:
                                guard_reasons = []
                            if guard_reasons:
                                st.markdown('**Why approval is required**:')
                                for gr in guard_reasons:
                                    st.markdown(f'- {gr}')
                            # Show exactly what will run, so the approver knows what they are approving.
                            if ap.get('canonical_args'):
                                st.markdown('**Exact arguments**:')
                                st.code(str(ap['canonical_args'])[:1000], language='json')

                            if is_approver:
                                col_a, col_d = st.columns(2)
                                with col_a:
                                    if st.button('✅ Approve', key=f'ap_{ap["id"]}'):
                                        # No resolved_by: the server records the authenticated identity.
                                        r = api_post(f'/approvals/{ap["id"]}', {'action': 'approved'}, timeout=5)
                                        if r.ok:
                                            st.success('Approved!')
                                            st.rerun()
                                        else:
                                            st.error(error_detail(r))
                                with col_d:
                                    if st.button('❌ Deny', key=f'dn_{ap["id"]}'):
                                        r = api_post(f'/approvals/{ap["id"]}', {'action': 'denied'}, timeout=5)
                                        if r.ok:
                                            st.warning('Denied.')
                                            st.rerun()
                                        else:
                                            st.error(error_detail(r))
                            else:
                                st.caption('⏳ Waiting for an approver to review this request.')
                else:
                    st.info('No pending approvals.')
            elif approvals_resp.status_code != 401:
                st.error(f'Could not load approvals: {error_detail(approvals_resp)}')
        except Exception:
            st.info('API not reachable.')

with tab_audit:
    st.subheader('Audit Log')
    col1, col2 = st.columns([3, 1])
    with col1:
        limit = st.slider('Max entries', 10, 500, 100)
    with col2:
        if st.button('Verify Chain Integrity'):
            try:
                r = api_get('/audit/verify')
                if r.ok:
                    result = r.json()
                    if result.get('ok'):
                        st.success(f"✅ Chain intact ({result.get('checked', 0)} entries)")
                    else:
                        st.error(f"⚠️ TAMPERED at seq={result.get('first_tampered_seq')}")
                else:
                    st.error(error_detail(r))
            except Exception as e:
                st.error(f'Error: {e}')
    try:
        r = api_get(f'/audit?limit={limit}')
        if r.ok:
            entries = r.json()
            if entries:
                import pandas as pd
                df = pd.DataFrame(entries)
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
                display_cols = ['timestamp', 'session_id', 'tool', 'verdict', 'risk_label', 'risk_score', 'result_summary']
                display_cols = [c for c in display_cols if c in df.columns]
                st.dataframe(df[display_cols], use_container_width=True)
            else:
                st.info('No audit log entries yet.')
        elif r.status_code != 401:
            st.error(f'Error loading audit log: {error_detail(r)}')
    except Exception as e:
        st.error(f'Error loading audit log: {e}')

with tab_replay:
    st.subheader('Session Replay')
    session_input = st.text_input('Session ID', value=st.session_state.current_session_id or '', placeholder='Enter session ID to replay')
    if st.button('Replay') and session_input:
        try:
            r = api_get(f'/replay/{session_input}')
            if r.ok:
                data = r.json()
                st.code(data.get('text', 'No replay data'), language=None)
            else:
                st.error(f'Error {r.status_code}: {error_detail(r)}')
        except Exception as e:
            st.error(f'Error: {e}')

with tab_reports:
    st.subheader('Post-Mortem Reports')
    with st.form('postmortem_form'):
        pm_session = st.text_input('Session ID', value=st.session_state.current_session_id or '')
        pm_title = st.text_input('Incident Title', value='Model Performance Incident')
        pm_diagnosis = st.text_area('Diagnosis / Summary', height=150)
        submitted = st.form_submit_button('Generate Post-Mortem')
    if submitted and pm_session and pm_diagnosis:
        with st.spinner('Generating report...'):
            try:
                r = api_post('/postmortem', {'session_id': pm_session, 'diagnosis': pm_diagnosis, 'title': pm_title}, timeout=600)
                if r.ok:
                    report = r.json().get('report', '')
                    st.markdown(report)
                    st.download_button('Download Report', data=report, file_name='postmortem.md', mime='text/markdown')
                else:
                    st.error(f'Error {r.status_code}: {error_detail(r)}')
            except Exception as e:
                st.error(f'Error: {e}')
