import io
import json
from collections.abc import Callable
from datetime import datetime
from itertools import takewhile
from typing import Any
from zipfile import ZipFile
import dateparser
import urllib3
from dateutil.parser import parse

# Disable insecure warnings
urllib3.disable_warnings()

# These parameters will be used for retry mechanism logging
TOTAL_RETRY_COUNT = 0

FULL_URL = None

# Valid Entity Type for Whitelists
VALID_ENTITY_TYPE = ["Users", "Activityaccount", "Resources", "Activityip"]

# Valid Whitelist Types
VALID_WHITELIST_TYPE = ["Global", "Attribute"]

# Special characters for spotter query
SPOTTER_SPECIAL_CHARACTERS = ["\\", "*", "?"]

# Markdown characters.
MARKDOWN_CHARS = r"\*_{}[]()#+-!"

# Mapping of user input of mirroring direction to XSOAR.
MIRROR_DIRECTION = {"None": None, "Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}

# If any comment is added to the incident, then this will be the action we'll get through incident activity history
# command.
COMMENT_ACTION = "COMMENTS_ADDED"

# If any file is attached to the incident, then this will be the action we'll get through incident activity history
# command.
ATTACHMENT_ACTION = "ATTACHED_FILE"

# This will store the state mapping of XSOAR states with Securonix states.
XSOAR_TO_SECURONIX_STATE_MAPPING: dict = {}

# Policy types for which retry should have end time to the current time.
POLICY_TYPES_TO_RETRY = ["DIRECTIVE", "LAND SPEED", "TIER2", "BEACONING"]

MESSAGE = {
    "INVALID_MAX_VALUE": "Please provide a value for 'max' between 1 and 10,000.",
}

def main():

    params = {
        # Connection
        "tenant": "a3t7vabb",
        "tenant_name": "",
        "host": "",
        "username": "shubham.k",
        "password": "Network@5714",

        # Network / security
        "unsecure": True,
        "proxy": False,

        # Retry / backoff
        "securonix_retry_count": 3,
        "securonix_retry_delay_type": "Exponential",
        "securonix_retry_delay": 60,

        # Fetch / incident behavior
        "fetch_time": "1 hour",
        "max_fetch": 200,
        "incident_status": "opened",
        "default_severity": "Medium",
        "close_incident": False,

        # Mirroring / remote
        "close_states_of_securonix": "",
        "entity_type_to_fetch": "Incident"
    }

#    remove_nulls_from_dictionary(params)

    host = params.get("host", None)
    tenant = params.get("tenant")
    if not host:
        server_url = tenant
        if not tenant.startswith("http://") and not tenant.startswith("https://"):
            server_url = f"https://{tenant}"  # noqa: E231
        if not tenant.endswith(".securonix.net/Snypr/ws/"):
            server_url += ".securonix.net/Snypr/ws/"
    else:
        host = host.rstrip("/")
        if not host.endswith("/ws"):
            host += "/ws/"
        server_url = host

    username = params.get("username")
    password = params.get("password")
    verify = not params.get("unsecure", False)
    proxy = params.get("proxy")
    # Updating TOTAL_RETRY_COUNT to get user provided value
    global TOTAL_RETRY_COUNT
    TOTAL_RETRY_COUNT = arg_to_number(
        params.get("securonix_retry_count", "0"),  # type: ignore
        arg_name="securonix_retry_count",
    )
    TOTAL_RETRY_COUNT = min(TOTAL_RETRY_COUNT, 5)
    securonix_retry_delay_type = params.get("securonix_retry_delay_type", "Exponential")
    securonix_retry_delay = arg_to_number(params.get("securonix_retry_delay", "30"), arg_name="securonix_retry_delay")
    if securonix_retry_delay <= 30:  # type: ignore
        securonix_retry_delay = 30
    elif securonix_retry_delay >= 300:  # type: ignore
        securonix_retry_delay = 300
    if securonix_retry_delay_type == "Exponential":
        securonix_retry_delay = int(securonix_retry_delay / 2)  # type: ignore
    # Create a state mapping from XSOAR to Securonix.
#    create_xsoar_to_securonix_state_mapping(params)

    command = "test-module"
    LOG(f"Command being called in Securonix is: {command}")

    try:
        client = Client(
            tenant=tenant,
            server_url=server_url,
            username=username,
            password=password,
            verify=verify,
            proxy=proxy,
            securonix_retry_count=TOTAL_RETRY_COUNT,  # type: ignore
            securonix_retry_delay=securonix_retry_delay,  # type: ignore[arg-type]
            securonix_retry_delay_type=securonix_retry_delay_type,
        )
        commands: dict[str, Callable[[Client, dict[str, str]], tuple[str, dict[Any, Any], dict[Any, Any]]]] = {
            "securonix-list-workflows": list_workflows,
            "securonix-get-default-assignee-for-workflow": get_default_assignee_for_workflow,
            "securonix-list-possible-threat-actions": list_possible_threat_actions,
            "securonix-list-policies": list_policies,
            "securonix-list-resource-groups": list_resource_groups,
            "securonix-list-users": list_users,
            "securonix-list-activity-data": list_activity_data,
            "securonix-list-incidents": list_incidents,
            "securonix-get-incident": get_incident,
            "securonix-get-incident-status": get_incident_status,
            "securonix-get-incident-workflow": get_incident_workflow,
            "securonix-get-incident-available-actions": get_incident_available_actions,
            "securonix-perform-action-on-incident": perform_action_on_incident,
            "securonix-add-comment-to-incident": add_comment_to_incident,
            "securonix-create-incident": create_incident,
            "securonix-list-watchlists": list_watchlists,
            "securonix-get-watchlist": get_watchlist,
            "securonix-create-watchlist": create_watchlist,
            "securonix-check-entity-in-watchlist": check_entity_in_watchlist,
            "securonix-add-entity-to-watchlist": add_entity_to_watchlist,
            "securonix-threats-list": list_threats,
            "securonix-incident-activity-history-get": get_incident_activity_history,  # type: ignore[dict-item]
            "securonix-whitelists-get": list_whitelists,  # type: ignore[dict-item]
            "securonix-whitelist-entry-list": get_whitelist_entry,
            "securonix-whitelist-entry-add": add_whitelist_entry,
            "securonix-whitelist-create": create_whitelist,
            "securonix-lookup-table-config-and-data-delete": delete_lookup_table_config_and_data,  # type: ignore
            "securonix-whitelist-entry-delete": delete_whitelist_entry,
            "securonix-lookup-tables-list": list_lookup_tables,  # type: ignore[dict-item]
            "securonix-lookup-table-entry-add": add_entry_to_lookup_table,  # type: ignore[dict-item]
            "securonix-lookup-table-entries-list": list_lookup_table_entries,  # type: ignore[dict-item]
            "securonix-lookup-table-create": create_lookup_table,
            "securonix-lookup-table-entries-delete": delete_lookup_table_entries,
        }
        if command == "fetch-incidents":
 #           validate_mirroring_parameters(params=params)

            fetch_time = params.get("fetch_time", "1 hour")
            tenant_name = params.get("tenant_name")
            incident_status = params.get("incident_status") if "incident_status" in params else "opened"
            default_severity = params.get("default_severity", "")
            max_fetch_ = arg_to_number(params.get("max_fetch", "200"), arg_name="max_fetch")
            max_fetch = str(min(200, max_fetch_))  # type: ignore
            last_run = json.loads(demisto.getLastRun().get("value", "{}"))
            close_incident = argToBoolean(params.get("close_incident", False))

            if params.get("entity_type_to_fetch") == "Threat":
                incidents = fetch_securonix_threat(client, fetch_time, tenant_name, max_fetch, last_run=last_run)
            else:
                incidents = fetch_securonix_incident(
                    client,
                    fetch_time,
                    incident_status,
                    default_severity,
                    max_fetch,
                    last_run=last_run,
                    close_incident=close_incident,
                )

            demisto.incidents(incidents)
        elif command == "securonix-list-violation-data":
            return_results(
                run_polling_command(
                    client=client,
                    args=demisto.args(),
                    search_function=list_violation_data,
                    command_name="securonix-list-violation-data",
                )
            )
        elif command == "test-module":
            demisto.results(test_module(client))
        elif command == "securonix-incident-attachment-get":
            return_results(get_incident_attachments(client=client, args=demisto.args()))
        elif command == "get-remote-data":
            close_states_of_securonix = params.get("close_states_of_securonix", "").strip().lower()
            close_states_of_securonix = argToList(close_states_of_securonix)

            return_results(get_remote_data_command(client, demisto.args(), close_states_of_securonix))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, demisto.args()))
        elif command == "securonix-xsoar-state-mapping-get":
            return_results(create_xsoar_to_securonix_state_mapping(params=params))
        elif command == "update-remote-system":
            return_results(update_remote_system(client, demisto.args()))
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()