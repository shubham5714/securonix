    params = {
        # Connection
        "tenant": "a3t7vabb",
        "tenant_name": "your-tenant",
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
        "entity_type_to_fetch": "Incident",
    }

    remove_nulls_from_dictionary(params)

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
    proxy = demisto.params().get("proxy") is True