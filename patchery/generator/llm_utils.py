import logging
import os
import re
import time
import datetime

from typing import List, Dict, Tuple

from litellm import completion, completion_cost
from ..utils import llm_cost, LLM_MAPPING

_l = logging.getLogger(__name__)


# def _retry_requests_connection(query_endpoint, query_headers, query_payload, model: str) -> Tuple[Dict, float]:
#     _l.debug(f"Start requests connection.")
#     while True:
#         try:
#             response = requests.post(query_endpoint, headers=query_headers, data=query_payload)
#             _l.info(f"litellm cost: {response.headers.get('x-litellm-response-cost')}")
#             cost = response.headers.get("x-litellm-response-cost")
#             if cost is None:
#                 litellm_cost = 0.0
#             else:
#                 litellm_cost = float(cost)
#             # Get the model that actually processed the request
#             used_model = response.headers.get("x-litellm-model")
#             # Check if we used a fallback model
#             if used_model and used_model != model:
#                 _l.info(f"Primary model failed, used fallback: {used_model}")
#             else:
#                 _l.info(f"Used primary model: {used_model}")
#         except requests.exceptions.ConnectionError as e:
#             _l.critical(f"connection error: {e}. Retrying.")
#             time.sleep(random.uniform(1.0, 5.0))
#             continue
#         if response.text == "":
#             _l.critical(f"Empty response, retrying.")
#             time.sleep(30)
#             continue
#         if response.status_code != 200:
#             _l.debug(f"URL failed, code: {response.status_code}")
#             _l.debug(f"response: {response.text}")
#             try:
#                 data = response.json()
#                 error_message = data.get("error", {}).get("message", None)
#                 if "Budget has been exceeded!" in error_message:
#                     _l.warning(f"Budget has been exceeded! EXITING.")
#                     sys.exit(1)
#                 if (
#                         "No deployments available for selected model" in error_message
#                         or "RateLimitError" in error_message
#                 ):
#                     _l.warning(f"Rate limited, retrying after 60 seconds.")
#                     time.sleep(60)
#                     continue
#
#                 time.sleep(30)
#                 _l.critical("Slept 30 seconds after an error. Retry.")
#                 continue
#
#             except Exception:
#                 _l.critical(
#                     "Unexpected error during retry_requests_connection(). Sleep 30 seconds before retrying.",
#                     exc_info=True,
#                 )
#                 time.sleep(30)
#                 _l.critical("Slept 30 seconds after an unexpected error. Retry.")
#                 continue
#         else:
#             return response.json(), litellm_cost
#     return {}, 0.0

def get_llm_backups(model: str) -> List[str]:
    if model == LLM_MAPPING.get('o4-mini'):
        return [LLM_MAPPING.get('o3-mini'), LLM_MAPPING.get('o3')]
    if model == LLM_MAPPING.get('o3-mini'):
        return [LLM_MAPPING.get('o4-mini'), LLM_MAPPING.get('o3')]
    if model == LLM_MAPPING.get('claude-3.7-sonnet'):
        return [LLM_MAPPING.get('gemini-2.5-pro'), LLM_MAPPING.get('o3-mini'), LLM_MAPPING.get('o4-mini')]
    if model == LLM_MAPPING.get('gemini-2.5-pro'):
        return [LLM_MAPPING.get('claude-3.7-sonnet'), LLM_MAPPING.get('gemini-2.0-flash')]
    return [LLM_MAPPING.get('claude-3.7-sonnet'), LLM_MAPPING.get('claude-3.5-sonnet'), LLM_MAPPING.get('gpt-4.1')]

def get_llm_params(model: str, temperature: float, enable_thinking = False) -> Tuple[float, str | None, dict | None]:
    """
    Get the LLM parameters based on the model and temperature.
    Args:
        model (str): The model name.
        temperature (int): The temperature value.
        enable_thinking (bool): Whether to enable thinking.
    Returns:
        Tuple[int, str | None, dict | None]: The temperature, reasoning effort, and think_param.
    """
    temperature = temperature
    reasoning_effort = None
    think_param = None
    if 'o1' in model or 'o3' in model or 'o4' in model:
        temperature = 1.0
        reasoning_effort = 'medium'
        if enable_thinking:
            reasoning_effort = 'high'
    if 'claude-3.7-sonnet' in model and enable_thinking:
        think_param = {"type": "enabled", "budget_tokens": 5000}

    return temperature, reasoning_effort, think_param

_l.setLevel(logging.DEBUG)


def post_llm_requests(messages: List[Dict], temperature: float, model: str, enable_thinking: bool = False) -> Tuple[
    dict, float]:
    reasoning_effort = None

    if os.getenv("LITELLM_KEY"):
        key = os.environ.get("LITELLM_KEY")
    else:
        raise ValueError(f"Missing LLM API KEY")
    #if os.getenv("AIXCC_LITELLM_HOSTNAME"):
    #    query_api = os.environ.get("AIXCC_LITELLM_HOSTNAME")
    #else:
    #    raise ValueError(f"Missing LLM API ENDPOINT URL")
    # if 'o1' in model or 'o3' in model or 'o4' in model:
    #     temperature = 1
    #     reasoning_effort = 'medium'
    #     if enable_thinking:
    #         reasoning_effort = 'high'
    # if 'claude-3.7-sonnet' in model and enable_thinking:
    #     _l.info(f"Claude Thinking is enabled")
    #     temperature = 1
    #     if enable_thinking:
    #         reasoning_effort = 'high'
    _l.info(f"🔍 Prompting with temperature: {temperature} and model: {model}")
    if model not in LLM_MAPPING.values():
        _l.warning(f"Unknown model: {model}")
        model = LLM_MAPPING.get('claude-3.7-sonnet')

    user_budget = _get_model_budget(model)
    if user_budget is None:
        raise RuntimeError(f"Unknown model: {model}")
    fallbacks = get_llm_backups(model)
    fallback_index = 0
    send_model = model
    # TODO: FIX ME
    send_model = "claude-3-7-sonnet-20250219"

    user_budget = _get_model_budget(model)
    while True:
        # TODO: put manual fallback calculation here
        try:
            adj_temperature, reasoning_effort, thinking_param = get_llm_params(send_model, temperature, enable_thinking)
            response = completion(
                model=send_model, messages=messages, api_key=key,
                temperature=adj_temperature, num_retries=3, timeout=30, user=user_budget,
                reasoning_effort=reasoning_effort, drop_params=True,
                # thinking=thinking_param,
            )
            break
        except Exception as e:
            current_minute = datetime.datetime.now().minute
            if current_minute % 30 == 0:
                _l.info(f"Budget reset per 30 mins, retry it")
                continue
            if fallback_index >= len(fallbacks):
                _l.critical(f"Failed to connect to LLM: {e}")
                fallback_index = 0
                send_model = model
                user_budget = _get_model_budget(model)
                time.sleep(30)
                continue
            print(e)
            send_model = fallbacks[fallback_index]
            _l.info(f"trying {send_model} instead")
            #user_budget = _get_model_budget(send_model)
            time.sleep(30)
            fallback_index += 1

    llm_response = response.json()
    _l.info("LLM response received successfully.")
    # current_llm_cost = completion_cost(llm_response)
    if 'additional_headers' not in response._hidden_params or 'llm_provider-x-litellm-response-cost' not in response._hidden_params['additional_headers']:
        _l.warning("No LLM cost found in response headers, using default cost of 0.0")
        current_llm_cost = 0.0
    else:
        current_llm_cost = float(response._hidden_params['additional_headers']['llm_provider-x-litellm-response-cost'])
    actual_model = llm_response['model']
    _l.info(f"💸 LLM cost: {current_llm_cost} and the model we actually use: {actual_model}")
    if llm_response is None:
        return {}, 0.0
    return llm_response, current_llm_cost


def _get_model_budget(model: str) -> str | None:
    budget = None
    if os.environ.get("ARTIPHISHELL_GLOBAL_ENV_IS_CI_LLM_BUDGET", None) == 'true':
        budget = 'patching-budget'
    else:
        if 'oai' in model or 'gpt' in model:
            budget = 'openai-budget'
        elif 'claude' in model:
            budget = 'claude-budget'
        elif 'gemini' in model:
            budget = 'gemini-budget'
    return budget


def parse_llm_output(response, model: str) -> str:
    output = response["choices"][0]["message"]
    content = output["content"]
    completion_tokens = response["usage"]["completion_tokens"]
    prompt_tokens = response["usage"]["prompt_tokens"]
    # cached_prompt_tokens = response["usage"]["prompt_tokens_details"]["cached_tokens"]
    cached_prompt_tokens = response["usage"].get("cache_read_input_tokens", 0)
    # _l.info(f"llm cost is {llm_cost(model, prompt_tokens, completion_tokens, cached_prompt_tokens)}")
    _l.debug(f"output content is {content}")
    return content


def parse_search_patch(patch_text):
    # Split the text into file/function blocks
    file_function_blocks = re.split(r'\n(?=File: )', patch_text.strip())
    patches = []
    for block in file_function_blocks:
        if not block.strip():
            continue
        # Extract the file name and function name
        file_function_match = re.match(r'File:\s+(.*?)\s+-\s+([a-zA-Z0-9_]+)\(', block)
        if not file_function_match:
            _l.debug(f"Failed to parse file and function from block:\n{block}")
            continue
        file_name = str(file_function_match.group(1).strip())
        function_name = str(file_function_match.group(2).strip())

        # Extract all code blocks associated with this function
        code_blocks = re.findall(r'```(.*?)```', block, re.DOTALL)
        search_replace_pairs = []
        for code_block in code_blocks:
            # Parse the search and replace code blocks
            code_pattern = r'<<<<<<< SEARCH\n(.*?)\n=======\n(.*?)\n>>>>>>> REPLACE'
            code_match = re.search(code_pattern, code_block, re.DOTALL)
            if code_match:
                search_code = str(code_match.group(1).rstrip())
                replace_code = str(code_match.group(2).rstrip())
                search_replace_pairs.append({
                    'search_code': search_code,
                    'replace_code': replace_code
                })
            else:
                _l.debug(f"Failed to parse code block for function {function_name} in file {file_name}")
        if search_replace_pairs:
            patches.append({
                'file_name': file_name,
                'function_name': function_name,
                'search_replace_pairs': search_replace_pairs
            })
    return patches


def replace_search_patch(function_code, search_code, replace_code):
    function_lines = function_code.splitlines()
    search_lines = search_code.splitlines()
    replace_lines = replace_code.splitlines()

    # Normalize lines by stripping leading/trailing whitespace
    function_lines_stripped = [line.strip() for line in function_lines]
    search_lines_stripped = [line.strip() for line in search_lines]
    # Search for the sequence search_lines_stripped in function_lines_stripped
    found = False
    for i in range(len(function_lines_stripped) - len(search_lines_stripped) + 1):
        match = True
        for j in range(len(search_lines_stripped)):
            if function_lines_stripped[i + j] != search_lines_stripped[j]:
                match = False
                break
        if match:
            # Track indentation preservation# Keep track of which replace lines have been processed
            processed_indices = set()
            # Map each search line to its corresponding replace line
            for s_i, s_line in enumerate(search_lines):
                s_indent = len(s_line) - len(s_line.lstrip())
                for r_i, r_line in enumerate(replace_lines):
                    # Only consider lines that haven't been processed yet
                    if r_i not in processed_indices and s_line.strip() == r_line.strip():
                        replace_lines[r_i] = ' ' * s_indent + r_line.strip()
                        processed_indices.add(r_i)
                        break
            found = True
            # Replace the lines
            function_lines = function_lines[:i] + replace_lines + function_lines[i + len(search_lines):]
            break  # Break after first replacement for this search-replace pair
    if not found:
        _l.debug("Search code not found in function.")
        return ''
    return '\n'.join(function_lines)
