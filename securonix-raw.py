category: Analytics & SIEM
provider: Securonix
sectionorder:
- Connect
- Collect
commonfields:
  id: Securonix
  version: -1
configuration:
- display: Host (Overrides the default hostname, https://{tenant}.net/Snypr)
  name: host
  type: 0
  required: false
  section: Connect
- display: Tenant
  name: tenant
  required: true
  type: 0
  section: Connect
- display: Username
  name: username
  required: true
  type: 0
  section: Connect
- display: Password
  name: password
  required: true
  type: 4
  section: Connect
- additionalinfo: The type of Securonix entity to fetch. Supported entities are "Incident" and "Threat".
  defaultvalue: Incident
  display: Type of entity to fetch
  name: entity_type_to_fetch
  options:
  - Incident
  - Threat
  type: 15
  required: false
  section: Collect
- additionalinfo: Name of the tenant to fetch threats from. This parameter is optional for Non MSSP users.
  display: Tenant Name
  name: tenant_name
  type: 0
  required: false
  section: Collect
- display: Fetch incidents
  name: isFetch
  type: 8
  required: false
  section: Collect
- additionalinfo: "Selecting \"all\" will fetch incidents updated in the given time range.\nSelecting \"opened\" will fetch incidents opened in the given time range.\nSelecting \"closed\" will fetch incidents closed in the given time range."
  defaultvalue: opened
  display: Incidents to fetch
  name: incident_status
  options:
  - All
  - opened
  - closed
  type: 15
  required: false
  section: Collect
- display: Set default incident severity
  name: default_severity
  options:
  - Low
  - Medium
  - High
  type: 15
  required: false
  section: Collect
- display: Incident type
  name: incidentType
  type: 13
  required: false
  section: Collect
- additionalinfo: "The date or relative timestamp from where to start fetching incidents.\n\nSupported formats: <number> <time unit>, e.g., 1 hour, 30 minutes, 7 days, 3 months, 1 year."
  defaultvalue: 1 hour
  display: First fetch time range
  name: fetch_time
  type: 0
  required: false
  section: Collect
- defaultvalue: '200'
  additionalinfo: If the value is greater than 200, it will be considered as 200. The maximum is 200.
  display: The maximum number of incidents to fetch each time.
  name: max_fetch
  type: 0
  required: false
  section: Collect
- additionalinfo: The mirroring direction in which to mirror the incidents. You can mirror "Incoming" (from Securonix to XSOAR), "Outgoing" (from XSOAR to Securonix), or in both directions.
  defaultvalue: None
  display: Incident Mirroring Direction
  name: mirror_direction
  options:
  - None
  - Incoming
  - Outgoing
  - Incoming And Outgoing
  type: 15
  required: false
  section: Collect
- additionalinfo: "If enabled, the integration will close the respective Securonix\nincident after fetching it in XSOAR. Following fields will be required for \nthis functionality:\n\n1. Securonix action name to map with XSOAR's active state for Outgoing mirroring\n2. Securonix status to map with XSOAR's active state for Outgoing mirroring\n3. Securonix action name to map with XSOAR's closed state for Outgoing mirroring\n4. Securonix status to map with XSOAR's closed state for Outgoing mirroring"
  display: Close respective Securonix incident after fetching
  name: close_incident
  type: 8
  required: false
  section: Collect
- additionalinfo: If the Securonix incident is in any one of the state mentioned here, then the incident will be Closed on XSOAR. Supports comma-separated values.
  display: Securonix workflow state(s) that can be considered as Close state in XSOAR for Incoming mirroring
  name: close_states_of_securonix
  type: 0
  required: false
  section: Collect
- additionalinfo: Provide an action name to map with XSOAR's active state. E.g. IN PROGRESS
  display: Securonix action name to map with XSOAR's active state for Outgoing mirroring
  name: active_state_action_mapping
  type: 0
  required: false
  section: Collect
- additionalinfo: Provide a workflow status to map with XSOAR's active state. E.g. In Progress
  display: Securonix status to map with XSOAR's active state for Outgoing mirroring
  name: active_state_status_mapping
  type: 0
  required: false
  section: Collect
- additionalinfo: Provide an action name to map with XSOAR's Closed state. E.g. CLOSED
  display: Securonix action name to map with XSOAR's closed state for Outgoing mirroring
  name: closed_state_action_mapping
  type: 0
  required: false
  section: Collect
- additionalinfo: Provide a workflow status to map with XSOAR's closed state. E.g. Completed
  display: Securonix status to map with XSOAR's closed state for Outgoing mirroring
  name: closed_state_status_mapping
  type: 0
  required: false
  section: Collect
- additionalinfo: Choose the tag to add to an entry to mirror it as a comment in Securonix.
  defaultvalue: comment
  display: Comment Entry Tag
  name: comment_tag
  type: 0
  required: false
  section: Collect
- additionalinfo: Numbers of retries to be performed. (Recommended is 3)
  defaultvalue: '3'
  display: Securonix Retry Count
  name: securonix_retry_count
  options:
  - '0'
  - '1'
  - '2'
  - '3'
  - '4'
  - '5'
  type: 15
  required: false
  section: Collect
- additionalinfo: The delay between two retries. Range in 30 to 300 Seconds (5 minutes). Anything less than 30 seconds is considered 30 seconds, and anything more than 300 seconds is considered 300 seconds. (Recommended is 30 seconds)
  defaultvalue: '30'
  display: Securonix Retry Delay
  name: securonix_retry_delay
  type: 0
  required: false
  section: Collect
- additionalinfo: Delay type of retry mechanism. (Recommended is Exponential)
  defaultvalue: Exponential
  display: Securonix Retry Delay Type
  name: securonix_retry_delay_type
  options:
  - Exponential
  - Fixed
  type: 15
  required: false
  section: Collect
- display: Trust any certificate (not secure)
  name: unsecure
  type: 8
  required: false
  section: Connect
  advanced: true
- display: Use system proxy settings
  name: proxy
  type: 8
  required: false
  section: Connect
  advanced: true
description: Use the Securonix integration to manage incidents, threats, lookup tables, whitelists and watchlists.
display: Securonix (Partner Contribution)
name: Securonix
script:
  commands:
  - description: Gets a list of all available workflows.
    name: securonix-list-workflows
    outputs:
    - contextPath: Securonix.Workflows.Workflow
      description: Workflow name.
      type: String
    - contextPath: Securonix.Workflows.Type
      description: Workflow type.
      type: String
    - contextPath: Securonix.Workflows.Value
      description: Workflow value.
      type: String
  - arguments:
    - description: Workflow name.
      name: workflow
      required: true
    description: Gets the default assignee for the specified workflow.
    name: securonix-get-default-assignee-for-workflow
    outputs:
    - contextPath: Securonix.Workflows.Workflow
      description: Workflow name.
      type: String
    - contextPath: Securonix.Workflows.Type
      description: Workflow type.
      type: String
    - contextPath: Securonix.Workflows.Value
      description: Workflow value.
      type: String
  - description: Gets a list available threat actions.
    name: securonix-list-possible-threat-actions
    outputs:
    - contextPath: Securonix.ThreatActions
      description: A list of threat actions.
      type: String
  - description: Gets a list of all policies.
    name: securonix-list-policies
    outputs:
    - contextPath: Securonix.Policies.CreatedBy
      description: Creator of the policy.
      type: String
    - contextPath: Securonix.Policies.CreatedOn
      description: Policy created date.
      type: Date
    - contextPath: Securonix.Policies.Criticality
      description: Policy criticality.
      type: String
    - contextPath: Securonix.Policies.Description
      description: Policy description.
      type: String
    - contextPath: Securonix.Policies.Hql
      description: Policy Hibernate Query Language.
      type: String
    - contextPath: Securonix.Policies.ID
      description: Policy ID.
      type: String
    - contextPath: Securonix.Policies.Name
      description: Policy name.
      type: String
  - description: Gets a list of resource groups.
    name: securonix-list-resource-groups
    outputs:
    - contextPath: Securonix.ResourceGroups.Name
      description: Resource group name.
      type: String
    - contextPath: Securonix.ResourceGroups.Type
      description: Resource group type.
      type: String
  - description: Gets a list of users.
    name: securonix-list-users
    outputs:
    - contextPath: Securonix.Users.LastName
      description: User last name.
      type: String
    - contextPath: Securonix.Users.SkipEncryption
      description: Whether user encryption was skipped.
      type: String
    - contextPath: Securonix.Users.Riskscore
      description: User risk score.
      type: String
    - contextPath: Securonix.Users.EmployeeID
      description: User Employee ID.
      type: String
    - contextPath: Securonix.Users.Masked
      description: Whether the user is masked.
      type: String
    - contextPath: Securonix.Users.Division
      description: User division.
      type: String
    - contextPath: Securonix.Users.Criticality
      description: User criticality.
      type: String
    - contextPath: Securonix.Users.Status
      description: User status.
      type: String
    - contextPath: Securonix.Users.Department
      description: User department.
      type: String
    - contextPath: Securonix.Users.Title
      description: User title.
      type: String
    - contextPath: Securonix.Users.FirstName
      description: User first name.
      type: String
    - contextPath: Securonix.Users.Email
      description: User email address.
      type: String
  - arguments:
    - description: Start date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss).
      name: from
      required: true
    - description: End date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss).
      name: to
      required: true
    - description: "Free-text query. For example, query=\"resourcegroupname=WindowsSnare and policyname=Possible Privilege Escalation - Self Escalation\".\nNote: Use the XSOAR automation browser to run the command if the \"query\" argument contains the special characters."
      name: query
    - defaultValue: '1000'
      description: Maximum number of activity records to retrieve. Maximum allowed value is 10000.
      name: max
    description: Gets a list of activity data for the specified resource group.
    name: securonix-list-activity-data
    outputs:
    - contextPath: Securonix.ActivityData.Accountname
      description: Account name.
      type: String
    - contextPath: Securonix.ActivityData.Accountresourcekey
      description: Account source key.
      type: String
    - contextPath: Securonix.ActivityData.Agentfilename
      description: Agent file name.
      type: String
    - contextPath: Securonix.ActivityData.Baseeventid
      description: Base event ID.
      type: String
    - contextPath: Securonix.ActivityData.Categorizedtime
      description: Categorized time.
      type: String
    - contextPath: Securonix.ActivityData.Categorybehavior
      description: Category behavior.
      type: String
    - contextPath: Securonix.ActivityData.Categoryobject
      description: Category object.
      type: String
    - contextPath: Securonix.ActivityData.Categoryseverity
      description: Category severity.
      type: String
    - contextPath: Securonix.ActivityData.Collectionmethod
      description: Collection method.
      type: String
    - contextPath: Securonix.ActivityData.Collectiontimestamp
      description: Collection timestamp.
      type: String
    - contextPath: Securonix.ActivityData.Customnumber1
      description: Custom number.
      type: Number
    - contextPath: Securonix.ActivityData.Customstring13
      description: Custom string.
      type: String
    - contextPath: Securonix.ActivityData.Customstring17
      description: Custom string.
      type: String
    - contextPath: Securonix.ActivityData.Customtime1
      description: Custom time.
      type: String
    - contextPath: Securonix.ActivityData.Customtime2
      description: Custom time.
      type: String
    - contextPath: Securonix.ActivityData.Datetime
      description: Date time.
      type: String
    - contextPath: Securonix.ActivityData.Dayofmonth
      description: Day of month.
      type: String
    - contextPath: Securonix.ActivityData.Dayofweek
      description: Day of week.
      type: String
    - contextPath: Securonix.ActivityData.Dayofyear
      description: Day of year.
      type: String
    - contextPath: Securonix.ActivityData.Destinationntdomain
      description: Destination NT domain.
      type: String
    - contextPath: Securonix.ActivityData.Destinationprocessname
      description: Destination process name.
      type: String
    - contextPath: Securonix.ActivityData.Destinationservicename
      description: Destination service name.
      type: String
    - contextPath: Securonix.ActivityData.Destinationuserid
      description: Destination user ID.
      type: String
    - contextPath: Securonix.ActivityData.Destinationusername
      description: Destination username.
      type: String
    - contextPath: Securonix.ActivityData.Deviceaddress
      description: Device address.
      type: String
    - contextPath: Securonix.ActivityData.Destinationuserprivileges
      description: Destination user privileges.
      type: String
    - contextPath: Securonix.ActivityData.Devicecustomstring4
      description: Device custom string.
      type: String
    - contextPath: Securonix.ActivityData.Deviceeventcategory
      description: Device event category.
      type: String
    - contextPath: Securonix.ActivityData.Deviceexternalid
      description: Device external ID.
      type: String
    - contextPath: Securonix.ActivityData.Devicehostname
      description: Device hostname.
      type: String
    - contextPath: Securonix.ActivityData.Ehash
      description: Event hash.
      type: String
    - contextPath: Securonix.ActivityData.EventID
      description: Event ID.
      type: String
    - contextPath: Securonix.ActivityData.Eventoutcome
      description: Event outcome.
      type: String
    - contextPath: Securonix.ActivityData.Eventtime
      description: Time the event occurred.
      type: String
    - contextPath: Securonix.ActivityData.Filepath
      description: File path.
      type: String
    - contextPath: Securonix.ActivityData.Filepermission
      description: File permission.
      type: String
    - contextPath: Securonix.ActivityData.Hour
      description: Date time hour.
      type: String
    - contextPath: Securonix.ActivityData.ID
      description: Activity ID.
      type: String
    - contextPath: Securonix.ActivityData.Ingestionnodeid
      description: Ingestion node ID.
      type: String
    - contextPath: Securonix.ActivityData.Ipaddress
      description: IP address.
      type: String
    - contextPath: Securonix.ActivityData.Ipaddress_Long
      description: IP address long.
      type: String
    - contextPath: Securonix.ActivityData.JobID
      description: Deprecated. Use the Securonix.ActivityData.Jobid field.
      type: String
    - contextPath: Securonix.ActivityData.Jobid
      description: Job ID.
      type: String
    - contextPath: Securonix.ActivityData.Jobstarttime
      description: Job start time.
      type: String
    - contextPath: Securonix.ActivityData.Message
      description: Message.
      type: String
    - contextPath: Securonix.ActivityData.Minute
      description: Date time minute.
      type: String
    - contextPath: Securonix.ActivityData.Month
      description: Month.
      type: String
    - contextPath: Securonix.ActivityData.Oldfileid
      description: Old file ID.
      type: String
    - contextPath: Securonix.ActivityData.Oldfilepath
      description: Old file path.
      type: String
    - contextPath: Securonix.ActivityData.Others
      description: Others.
      type: String
    - contextPath: Securonix.ActivityData.Poprocessedtime
      description: PO processed time.
      type: String
    - contextPath: Securonix.ActivityData.Publishedtime
      description: Published time.
      type: String
    - contextPath: Securonix.ActivityData.Rawevent
      description: Raw event.
      type: String
    - contextPath: Securonix.ActivityData.Raweventsize
      description: Raw event size.
      type: String
    - contextPath: Securonix.ActivityData.Receivedtime
      description: Received time.
      type: String
    - contextPath: Securonix.ActivityData.Resourcename
      description: Resource name.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupCategory
      description: Resource group category.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupFunctionality
      description: Resource group functionality.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupID
      description: Resource group ID.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupName
      description: Resource group name.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupTimezoneoffset
      description: Resource Group Timezone offset.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupTypeID
      description: Resource group resource type ID.
      type: String
    - contextPath: Securonix.ActivityData.ResourceGroupVendor
      description: Resource group vendor.
      type: String
    - contextPath: Securonix.ActivityData.Resourcegroupid
      description: Resource Group ID.
      type: String
    - contextPath: Securonix.ActivityData.Resourcegroupname
      description: Resource Group Name.
      type: String
    - contextPath: Securonix.ActivityData.Resourcehostname
      description: Resource host name.
      type: String
    - contextPath: Securonix.ActivityData.Resourcehostname_Long
      description: Resource host name long.
      type: String
    - contextPath: Securonix.ActivityData.Resourcename
      description: Resource name.
      type: String
    - contextPath: Securonix.ActivityData.Resourcetype
      description: Resource type.
      type: String
    - contextPath: Securonix.ActivityData.Sessionid
      description: Session ID.
      type: String
    - contextPath: Securonix.ActivityData.Sourceaddress
      description: Source address.
      type: String
    - contextPath: Securonix.ActivityData.Sourceaddress_Long
      description: Source address long.
      type: String
    - contextPath: Securonix.ActivityData.Sourcehostname
      description: Source hostname.
      type: String
    - contextPath: Securonix.ActivityData.Sourcentdomain
      description: Source domain.
      type: String
    - contextPath: Securonix.ActivityData.Sourceport
      description: Source port.
      type: String
    - contextPath: Securonix.ActivityData.Sourceprocessname
      description: Source process name.
      type: String
    - contextPath: Securonix.ActivityData.Sourceuserid
      description: Source user ID.
      type: String
    - contextPath: Securonix.ActivityData.Sourceusername
      description: Source username.
      type: String
    - contextPath: Securonix.ActivityData.TenantID
      description: Tenant ID.
      type: String
    - contextPath: Securonix.ActivityData.Tenantname
      description: Tenant name.
      type: String
    - contextPath: Securonix.ActivityData.Timeline
      description: Time when the activity occurred, in Epoch time.
      type: String
    - contextPath: Securonix.ActivityData.Timeline_By_Hour
      description: Timeline by hour.
      type: String
    - contextPath: Securonix.ActivityData.Timeline_By_Minute
      description: Timeline by minute.
      type: String
    - contextPath: Securonix.ActivityData.Timeline_By_Month
      description: Timeline by month.
      type: String
    - contextPath: Securonix.ActivityData.Timeline_By_Week
      description: Timeline by week.
      type: String
    - contextPath: Securonix.ActivityData.Timestamp
      description: Timestamp.
      type: String
    - contextPath: Securonix.ActivityData.Transactionstring1
      description: Transaction string 1.
      type: String
    - contextPath: Securonix.ActivityData.Userid
      description: User ID.
      type: String
    - contextPath: Securonix.ActivityData.Week
      description: Week.
      type: String
    - contextPath: Securonix.ActivityData.Year
      description: Year.
      type: String
    - contextPath: Securonix.ActivityData._Indexed_At_Tdt
      description: Indexed at TDT.
      type: String
    - contextPath: Securonix.ActivityData._Version_
      description: Activity version.
      type: String
    - contextPath: Securonix.Activity.totalDocuments
      description: Total number of events.
      type: Number
    - contextPath: Securonix.Activity.message
      description: Message from the API.
      type: String
    - contextPath: Securonix.Activity.queryId
      description: Query Id for the pagination.
      type: String
    - contextPath: Securonix.Activity.command_name
      description: The command name.
      type: String
  - arguments:
    - description: Start date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss).
      name: from
      required: true
    - description: End date/time for which to retrieve activity data (in the format MM/dd/yyyy HH:mm:ss).
      name: to
      required: true
    - description: "Free-text query, For example, query=\"resourcegroupname=WindowsSnare and policyname=Possible Privilege Escalation - Self Escalation\".\nNote: Use the XSOAR automation browser to run the command if the \"query\" argument contains the special characters."
      name: query
    - description: Paginate next set of results.
      name: query_id
    - description: 'Provide the policy type for retrying if the violations are not found in the initial attempt. The types of policies that can be retried are: "Land Speed", "TIER2", "DIRECTIVE", "BEACONING".'
      name: policy_type
    - defaultValue: '1000'
      description: Maximum number of violations to retrieve.
      name: max
    description: Gets a list activity data for an account name.
    name: securonix-list-violation-data
    polling: true
    outputs:
    - contextPath: Securonix.ViolationData.Accountname
      description: Account name.
      type: String
    - contextPath: Securonix.ViolationData.Agentfilename
      description: Agent file name.
      type: String
    - contextPath: Securonix.ViolationData.Baseeventid
      description: Base event ID.
      type: String
    - contextPath: Securonix.ViolationData.Categorybehavior
      description: Category behavior.
      type: String
    - contextPath: Securonix.ViolationData.Category
      description: Violation category.
      type: String
    - contextPath: Securonix.ViolationData.Categoryobject
      description: Category object.
      type: String
    - contextPath: Securonix.ViolationData.Categoryseverity
      description: Category severity.
      type: String
    - contextPath: Securonix.ViolationData.Destinationaddress
      description: Destination address.
      type: String
    - contextPath: Securonix.ViolationData.Destinationntdomain
      description: Destination nt domain.
      type: String
    - contextPath: Securonix.ViolationData.Destinationuserid
      description: Destination user ID.
      type: String
    - contextPath: Securonix.ViolationData.Gestinationusername
      description: Destination username.
      type: String
    - contextPath: Securonix.ViolationData.Deviceaddress
      description: Device address.
      type: String
    - contextPath: Securonix.ViolationData.Deviceeventcategory
      description: Device event category.
      type: String
    - contextPath: Securonix.ViolationData.Deviceexternalid
      description: Device external ID.
      type: String
    - contextPath: Securonix.ViolationData.Devicehostname
      description: Device hostname.
      type: String
    - contextPath: Securonix.ViolationData.EventID
      description: Event ID.
      type: String
    - contextPath: Securonix.ViolationData.Eventoutcome
      description: Event outcome.
      type: String
    - contextPath: Securonix.ViolationData.Eventtime
      description: Time the event occurred.
      type: String
    - contextPath: Securonix.ViolationData.Generationtime
      description: Time that the violation was generated in Securonix.
      type: String
    - contextPath: Securonix.ViolationData.Invalid
      description: Whether the violation is valid.
      type: String
    - contextPath: Securonix.ViolationData.JobID
      description: Job ID.
      type: String
    - contextPath: Securonix.ViolationData.Jobstarttime
      description: Job start time.
      type: String
    - contextPath: Securonix.ViolationData.Policyname
      description: Policy name.
      type: String
    - contextPath: Securonix.ViolationData.Resourcename
      description: Resource name.
      type: String
    - contextPath: Securonix.ViolationData.ResourceGroupID
      description: Resource group ID.
      type: String
    - contextPath: Securonix.ViolationData.ResourceGroupName
      description: Resource group name.
      type: String
    - contextPath: Securonix.ViolationData.Riskscore
      description: Risk score.
      type: String
    - contextPath: Securonix.ViolationData.Riskthreatname
      description: Risk threat name.
      type: String
    - contextPath: Securonix.ViolationData.Sessionid
      description: Session ID.
      type: String
    - contextPath: Securonix.ViolationData.Sourcehostname
      description: Source hostname.
      type: String
    - contextPath: Securonix.ViolationData.Sourcentdomain
      description: Source nt domain.
      type: String
    - contextPath: Securonix.ViolationData.Sourceuserid
      description: Source user ID.
      type: String
    - contextPath: Securonix.ViolationData.Sourceusername
      description: Source username.
      type: String
    - contextPath: Securonix.ViolationData.Sourceuserprivileges
      description: Source user privileges.
      type: String
    - contextPath: Securonix.ViolationData.TenantID
      description: Tenant ID.
      type: String
    - contextPath: Securonix.ViolationData.Tenantname
      description: Tenant name.
      type: String
    - contextPath: Securonix.ViolationData.Timeline
      description: Time when the activity occurred, in Epoch time.
      type: String
    - contextPath: Securonix.ViolationData.Createdate
      description: Create date.
      type: String
    - contextPath: Securonix.ViolationData.Criticality
      description: Violation criticality.
      type: String
    - contextPath: Securonix.ViolationData.DataSourceID
      description: Data source ID.
      type: String
    - contextPath: Securonix.ViolationData.Department
      description: Department affected by the violation.
      type: String
    - contextPath: Securonix.ViolationData.EmployeeID
      description: Employee ID.
      type: String
    - contextPath: Securonix.ViolationData.Encrypted
      description: Whether the violation is encrypted.
      type: String
    - contextPath: Securonix.ViolationData.Firstname
      description: First name of the user that violated the policy.
      type: String
    - contextPath: Securonix.ViolationData.Fullname
      description: Full name of the user that violated the policy.
      type: String
    - contextPath: Securonix.ViolationData.ID
      description: ID of the user that violated the policy.
      type: String
    - contextPath: Securonix.ViolationData.LanID
      description: LAN ID associated with the policy violation.
      type: String
    - contextPath: Securonix.ViolationData.Lastname
      description: Last name of the user that violated the policy.
      type: String
    - contextPath: Securonix.ViolationData.Lastsynctime
      description: Last sync time, in Epoch time.
      type: String
    - contextPath: Securonix.ViolationData.Masked
      description: Whether the violation is masked.
      type: String
    - contextPath: Securonix.ViolationData.Mergeuniquecode
      description: Merge unique code.
      type: String
    - contextPath: Securonix.ViolationData.Riskscore
      description: Risk score.
      type: String
    - contextPath: Securonix.ViolationData.Skipencryption
      description: Skip encryption.
      type: String
    - contextPath: Securonix.ViolationData.Status
      description: Status of the policy violation.
      type: String
    - contextPath: Securonix.ViolationData.Timezoneoffset
      description: Timezone offset.
      type: String
    - contextPath: Securonix.ViolationData.Title
      description: Title.
      type: String
    - contextPath: Securonix.ViolationData.Uniquecode
      description: Unique code.
      type: String
    - contextPath: Securonix.ViolationData.UserID
      description: Last sync time, in Epoch time.
      type: String
    - contextPath: Securonix.ViolationData.Workemail
      description: Work email address of the user that violated the policy.
      type: String
    - contextPath: Securonix.ViolationData.Violator
      description: Violator.
      type: String
    - contextPath: Securonix.Violation.totalDocuments
      description: Total number of events.
      type: Number
    - contextPath: Securonix.Violation.message
      description: Message from the API.
      type: String
    - contextPath: Securonix.Violation.queryId
      description: Query Id for the pagination.
      type: String
  - arguments:
    - description: ' Start time range for which to return incidents (<number> <time unit>, e.g., 1 hour, 30 minutes).'
      name: from
      required: true
    - description: End date/time for which to retrieve incidents (in the format MM/dd/yyyy HH:mm:ss) Default is current time.
      name: to
    - description: The incident type. Can be "updated", "opened", or "closed". Supports multiple selections.
      name: incident_types
    - defaultValue: '50'
      description: Maximum number of incidents to retrieve.
      name: max
    description: Gets a list of incidents.
    name: securonix-list-incidents
    outputs:
    - contextPath: Securonix.Incidents.ViolatorID
      description: Incident Violator ID.
      type: String
    - contextPath: Securonix.Incidents.Entity
      description: Incident entity.
      type: String
    - contextPath: Securonix.Incidents.Riskscore
      description: Incident risk score.
      type: Number
    - contextPath: Securonix.Incidents.Priority
      description: Incident priority.
      type: String
    - contextPath: Securonix.Incidents.Reason
      description: Reason for the incident. Usually includes policy name and/or possible threat name.
      type: String
    - contextPath: Securonix.Incidents.IncidentStatus
      description: Incident status.
      type: String
    - contextPath: Securonix.Incidents.WorkflowName
      description: Incident workflow name.
      type: String
    - contextPath: Securonix.Incidents.Watchlisted
      description: Whether the incident is in a watchlist.
      type: Boolean
    - contextPath: Securonix.Incidents.IncidentType
      description: Incident type.
      type: String
    - contextPath: Securonix.Incidents.IncidentID
      description: Incident ID.
      type: String
    - contextPath: Securonix.Incidents.LastUpdateDate
      description: Last update date of the incident in Epoch time.
      type: Number
    - contextPath: Securonix.Incidents.Url
      description: URL that links to the incident on Securonix.
      type: String
    - contextPath: Securonix.Incidents.ViolatorText
      description: Incident violator text.
      type: String
    - contextPath: Securonix.Incidents.AssignedUser
      description: User assigned to the incident.
      type: String
    - contextPath: Securonix.Incidents.IsWhitelisted
      description: Whether the incident is added to allow list.
      type: Boolean
    - contextPath: Securonix.Incidents.Policystarttime
      description: Epoch time when the policy is first violated.
      type: Number
    - contextPath: Securonix.Incidents.Policyendtime
      description: Epoch time when the policy is last violated.
      type: Number
    - contextPath: Securonix.Incidents.Solrquery
      description: Spotter query to fetch the related violations.
      type: String
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    description: Gets details of the specified incident.
    name: securonix-get-incident
    outputs:
    - contextPath: Securonix.Incidents.ViolatorID
      description: Incident violator ID.
      type: String
    - contextPath: Securonix.Incidents.Entity
      description: Incident entity.
      type: String
    - contextPath: Securonix.Incidents.Riskscore
      description: Incident risk score.
      type: Number
    - contextPath: Securonix.Incidents.Priority
      description: Incident priority.
      type: String
    - contextPath: Securonix.Incidents.Reason
      description: Reason for the incident. Usually includes policy name and/or possible threat name.
      type: String
    - contextPath: Securonix.Incidents.IncidentStatus
      description: Incident status.
      type: String
    - contextPath: Securonix.Incidents.WorkflowName
      description: Incident workflow name.
      type: String
    - contextPath: Securonix.Incidents.Watchlisted
      description: Whether the incident is in a watchlist.
      type: Boolean
    - contextPath: Securonix.Incidents.IncidentType
      description: Incident type.
      type: String
    - contextPath: Securonix.Incidents.IncidentID
      description: Incident ID.
      type: String
    - contextPath: Securonix.Incidents.LastUpdateDate
      description: The time when the incident was last updated, in Epoch time.
      type: Number
    - contextPath: Securonix.Incidents.Url
      description: URL that links to the incident on Securonix.
      type: String
    - contextPath: Securonix.Incidents.ViolatorText
      description: Incident violator text.
      type: String
    - contextPath: Securonix.Incidents.AssignedUser
      description: User assigned to the incident.
      type: String
    - contextPath: Securonix.Incidents.IsWhitelisted
      description: Whether the incident is added to allow list.
      type: Boolean
    - contextPath: Securonix.Incidents.Policystarttime
      description: Epoch time when the policy is first violated.
      type: Number
    - contextPath: Securonix.Incidents.Policyendtime
      description: Epoch time when the policy is last violated.
      type: Number
    - contextPath: Securonix.Incidents.Solrquery
      description: Spotter query to fetch the related violations.
      type: String
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    description: Gets the status of the specified incident.
    name: securonix-get-incident-status
    outputs:
    - contextPath: Securonix.Incidents.IncidentStatus
      description: Incident status.
      type: String
    - contextPath: Securonix.Incidents.IncidentID
      description: Incident ID.
      type: String
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    description: Gets the workflow of the specified incident.
    name: securonix-get-incident-workflow
    outputs:
    - contextPath: Securonix.Incidents.Workflow
      description: Incident workflow.
      type: String
    - contextPath: Securonix.Incidents.IncidentID
      description: Incident ID.
      type: String
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    description: Gets a list of available actions for the specified incident.
    name: securonix-get-incident-available-actions
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    - auto: PREDEFINED
      description: 'Action to perform on the incident. You can see them using securonix-get-incident-available-actions. e.g: "CLAIM", "ASSIGN TO SECOPS", "ASSIGN TO ANALYST", "RELEASE", or "COMMENT".'
      name: action
      predefined:
      - ''
      required: true
    - description: 'The parameters, if needed, to perform the action. For example, for the ASSIGN TO ANALYST action: assigntouserid={user_id},assignedTo=USER.'
      name: action_parameters
    description: Performs an action on the specified incident.
    name: securonix-perform-action-on-incident
  - arguments:
    - description: Incident ID.
      name: incident_id
      required: true
    - description: Comment to add to the incident.
      name: comment
      required: true
    description: Adds a comment to the specified incident.
    execution: true
    name: securonix-add-comment-to-incident
  - description: Gets a list of watchlists.
    name: securonix-list-watchlists
    outputs:
    - contextPath: Securonix.WatchlistsNames
      description: Watchlist names.
      type: String
  - arguments:
    - description: Watchlist name.
      name: watchlist_name
      required: true
    description: Gets information for the specified watchlist.
    name: securonix-get-watchlist
    outputs:
    - contextPath: Securonix.Watchlists.TenantID
      description: Watchlist tenant ID.
      type: String
    - contextPath: Securonix.Watchlists.Tenantname
      description: Watchlist tenant name.
      type: String
    - contextPath: Securonix.Watchlists.Type
      description: Watchlist type.
      type: String
    - contextPath: Securonix.Watchlists.Watchlistname
      description: Watchlist name.
      type: String
    - contextPath: Securonix.Watchlists.Events.ExpiryDate
      description: Expiration date of the entity in the watchlist, in Epoch time.
      type: String
    - contextPath: Securonix.Watchlists.Events.Workemail
      description: Work email address of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Fullname
      description: Full name of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Reason
      description: Reason that the entity is in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.LanID
      description: Lan ID of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Lastname
      description: Last name of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.EntityName
      description: Entity name of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Title
      description: Title of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Firstname
      description: First name of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.EmployeeID
      description: Employee ID of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Masked
      description: Whether the entity in the watchlist is masked.
      type: String
    - contextPath: Securonix.Watchlists.Events.Division
      description: Division of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Departmant
      description: Department of the entity in the watchlist.
      type: String
    - contextPath: Securonix.Watchlists.Events.Status
      description: Status of the entity in the watchlist.
      type: String
  - arguments:
    - description: The name of the watchlist.
      name: watchlist_name
      required: true
    - description: "Name of the tenant the watchlist belongs to.\n\nThe tenant name parameter is required for MSSP users."
      name: tenant_name
    description: Creates a watchlist in Securonix.
    name: securonix-create-watchlist
    outputs:
    - contextPath: Securonix.Watchlists.Watchlistname
      description: Name of the Watchlist.
      type: String
    - contextPath: Securonix.Watchlists.TenantName
      description: Tenant Name.
      type: String
  - arguments:
    - description: 'The name of the entity to check. For example: 1002.'
      name: entity_name
      required: true
    - description: The name of the watchlist in which to check the entity.
      name: watchlist_name
      required: true
    description: Checks if the specified entity is in a watchlist.
    name: securonix-check-entity-in-watchlist
    outputs:
    - contextPath: Securonix.EntityInWatchlist.Watchlistnames
      description: The names of the watchlists in which the entity appears.
      type: String
    - contextPath: Securonix.EntityInWatchlist.EntityID
      description: The entity ID.
      type: String
  - arguments:
    - description: The name of the watchlist to which to add the entity.
      name: watchlist_name
      required: true
    - auto: PREDEFINED
      description: The entity type. Can be "Users", "Activityaccount", "RGActivityaccount", "Resources", or "Activityip".
      name: entity_type
      predefined:
      - Users
      - Activityaccount
      - RGActivityaccount
      - Resources
      - Activityip
      required: true
    - description: 'The name of the entity to add to the watchlist. For example: 1022.'
      name: entity_name
      required: true
    - defaultValue: '30'
      description: The number of days after which the entity will be removed from the watchlist. The default value is "30".
      name: expiry_days
    description: Adds an entity to a watchlist.
    name: securonix-add-entity-to-watchlist
  - arguments:
    - description: 'The violation name or policy name. For example: "Uploads to personal Websites".'
      name: violation_name
      required: true
    - description: 'The resource group name. For example: "BLUECOAT", "Palo Alto Firewall".'
      name: resource_group
      required: true
    - auto: PREDEFINED
      description: The entity type. Can be "Users", "Activityaccount", "RGActivityaccount", "Resources", or "Activityip".
      name: entity_type
      predefined:
      - Users
      - Activityaccount
      - RGActivityaccount
      - Resources
      - Activityip
      required: true
    - description: The entity name associated with the violation. Can be "LanID" or "Workemail". For more information, see the Securonix documentation.
      name: entity_name
      required: true
    - auto: PREDEFINED
      description: The action name. Can be "Mark as concern and create incident", "Non-Concern", or "Mark in progress (still investigating)".
      name: action_name
      predefined:
      - Mark as concern and create incident
      - Non-Concern
      - Mark in progress (still investigating)
      required: true
    - description: 'The resource name. For example: "BLUECOAT", "Palo Alto Firewall".'
      name: resource_name
      required: true
    - auto: PREDEFINED
      description: The incident severity (criticality) for the new incident. Can be "Low", "High", or "Critical".
      name: criticality
      predefined:
      - Low
      - High
      - Critical
    - description: A comment for the new incident.
      name: comment
    - auto: PREDEFINED
      description: The workflow name. This argument is optional, but required when the action_name argument is set to "Mark as concern and create incident". Can be "SOCTeamReview", "ActivityOutlierWorkflow", or "AccessCertificationWorkflow".
      name: workflow
      predefined:
      - SOCTeamReview
      - ActivityOutlierWorkflow
      - AccessCertificationWorkflow
    description: Creates an incident. For more information about the required arguments, see the Securonix documentation.
    name: securonix-create-incident
    outputs:
    - contextPath: Securonix.Incidents.ViolatorID
      description: The ID of the incident violator.
      type: String
    - contextPath: Securonix.Incidents.Entity
      description: The incident entity.
      type: String
    - contextPath: Securonix.Incidents.Riskscore
      description: The incident risk score.
      type: Number
    - contextPath: Securonix.Incidents.Priority
      description: The incident priority.
      type: String
    - contextPath: Securonix.Incidents.Reason
      description: The reason that the incident was created. Usually includes the policy name and/or possible threat name.
      type: String
    - contextPath: Securonix.Incidents.IncidentStatus
      description: The incident status.
      type: String
    - contextPath: Securonix.Incidents.WorkflowName
      description: The incident workflow name.
      type: String
    - contextPath: Securonix.Incidents.Watchlisted
      description: Whether the incident is in a watchlist.
      type: Boolean
    - contextPath: Securonix.Incidents.IncidentType
      description: The incident type.
      type: String
    - contextPath: Securonix.Incidents.IncidentID
      description: The incident ID.
      type: String
    - contextPath: Securonix.Incidents.LastUpdateDate
      description: The time when the incident was last updated, in Epoch time.
      type: Number
    - contextPath: Securonix.Incidents.Url
      description: The URL that links to the incident on Securonix.
      type: String
    - contextPath: Securonix.Incidents.ViolatorText
      description: Text of the incident violator.
      type: String
    - contextPath: Securonix.Incidents.AssignedUser
      description: The user assigned to the incident.
      type: String
    - contextPath: Securonix.Incidents.IsWhitelisted
      description: Whether the incident is added to allow list.
      type: Boolean
  - arguments:
    - description: "Start time range for which to return threats (Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ\nFor example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z)."
      name: date_from
      required: true
    - description: "End date/time for which to retrieve threats (Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ\nFor example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z) Default is current time."
      name: date_to
    - defaultValue: '10'
      description: The number of results to retrieve.
      name: page_size
    - description: Name of the tenant to fetch threats from. This parameter is optional for Non MSSP users.
      name: tenant_name
    - defaultValue: '0'
      description: Sets the starting index for the returned results.
      name: offset
    description: Retrieve a list of threats violated within a specified time range and get details about the threat models and policies violated.
    name: securonix-threats-list
    outputs:
    - contextPath: Securonix.Threat.TenantID
      description: Tenant ID.
      type: Number
    - contextPath: Securonix.Threat.Tenantname
      description: Tenant Name.
      type: String
    - contextPath: Securonix.Threat.Violator
      description: Violator of threat.
      type: String
    - contextPath: Securonix.Threat.EntityID
      description: Threat entity ID.
      type: String
    - contextPath: Securonix.Threat.Resourcegroupname
      description: Name of the resource group.
      type: String
    - contextPath: Securonix.Threat.ThreatName
      description: Threat Name.
      type: String
    - contextPath: Securonix.Threat.Category
      description: Category of threat.
      type: String
    - contextPath: Securonix.Threat.Resourcename
      description: Name of the resource.
      type: String
    - contextPath: Securonix.Threat.Resourcetype
      description: Type of the resource.
      type: String
    - contextPath: Securonix.Threat.GenerationTime
      description: Date and Time when the threat is generated.
      type: Date
    - contextPath: Securonix.Threat.GenerationTime_Epoch
      description: Epoch time when the threat is generated.
      type: Number
    - contextPath: Securonix.Threat.Policies
      description: List of policies violated.
      type: Unknown
    - contextPath: Securonix.Threat.Policystarttime
      description: Epoch time when the policy is first violated.
      type: Number
    - contextPath: Securonix.Threat.Policyendtime
      description: Epoch time when the policy is last violated.
      type: Number
    - contextPath: Securonix.Threat.Solrquery
      description: Spotter query to fetch the related violations.
      type: String
  - arguments:
    - description: Incident ID for which to retrieve the activity history.
      name: incident_id
      required: true
    description: Retrieves incident activity history for a specified incident.
    name: securonix-incident-activity-history-get
    outputs:
    - contextPath: Securonix.IncidentHistory.caseid
      description: Incident ID.
      type: Number
    - contextPath: Securonix.IncidentHistory.actiontaken
      description: The type of action taken.
      type: String
    - contextPath: Securonix.IncidentHistory.status
      description: The status of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.comment.Comments
      description: Comment text.
      type: String
    - contextPath: Securonix.IncidentHistory.eventTime
      description: Timestamp in epoch when the action is taken.
      type: Number
    - contextPath: Securonix.IncidentHistory.username
      description: Username of the person who carried out the action.
      type: String
    - contextPath: Securonix.IncidentHistory.currentassignee
      description: The current assignee of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.commentType
      description: The type of the comment.
      type: String
    - contextPath: Securonix.IncidentHistory.currWorkflow
      description: The current workflow of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.isPlayBookOutAvailable
      description: Whether or not the playbook is available.
      type: Boolean
    - contextPath: Securonix.IncidentHistory.creator
      description: The creator of the activity.
      type: String
    - contextPath: Securonix.IncidentHistory.lastStatus
      description: The previous status of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.pastassignee
      description: The previous assignee of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.prevWorkflow
      description: The previous workflow of the incident.
      type: String
    - contextPath: Securonix.IncidentHistory.attachment
      description: The name of the attached file.
      type: String
    - contextPath: Securonix.IncidentHistory.attachmentType
      description: The type of the attachment.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.playBookId
      description: The ID of the playbook.
      type: Number
    - contextPath: Securonix.IncidentHistory.playBookOutput.playBookName
      description: The name of the playbook.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.playRunId
      description: The playbook run ID.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.executorId
      description: The ID of the executor.
      type: Number
    - contextPath: Securonix.IncidentHistory.playBookOutput.executor
      description: The name of the executor.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.taskName
      description: The name of the playbook task.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.description
      description: The description of the playbook task.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.icon
      description: Playbook icon.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.taskId
      description: The ID of the playbook task.
      type: Number
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.lastExecutedTime
      description: The last execution time in epoch.
      type: Date
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.lastStatus
      description: The last status of the playbook.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.executedTask.executionId
      description: The execution ID of the playbook.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.executedTask.taskStartTime
      description: The start time of the task.
      type: Date
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.executedTask.taskEndTime
      description: The end time of the task.
      type: Date
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.executedTask.status
      description: The status of the task.
      type: String
    - contextPath: Securonix.IncidentHistory.playBookOutput.tasksForParticularRun.connectionMetadata
      description: Connection metadata.
      type: String
  - arguments:
    - description: Incident ID for which to retrieve the attachments.
      name: incident_id
      required: true
    - description: The type of attachment to retrieve. Supported options are csv, pdf, and txt. Comma-separated values are supported.
      name: attachment_type
    - description: 'Start time for which to retrieve attachments.(Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, yyyy-MM-ddTHH:mm:ss.SSSZ. For example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z, 2023-01-26T14:05:44.000Z).'
      name: from
    - description: 'End time for which to retrieve attachments.(Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ, yyyy-MM-ddTHH:mm:ss.SSSZ. For example: 01 Jan 2023, 01 Feb 2023 04:45:33, 2023-01-26T14:05:44Z, 2023-01-26T14:05:44.000Z).'
      name: to
    description: Retrieves the attachments available on the Securonix platform.
    name: securonix-incident-attachment-get
    outputs:
    - contextPath: File.Size
      description: The size of the file in bytes.
      type: Number
    - contextPath: File.SHA1
      description: The SHA1 hash of the file.
      type: String
    - contextPath: File.SHA256
      description: The SHA256 hash of the file.
      type: String
    - contextPath: File.SHA512
      description: The SHA512 hash of the file.
      type: String
    - contextPath: File.Name
      description: The name of the file.
      type: String
    - contextPath: File.SSDeep
      description: The SSDeep hash of the file.
      type: String
    - contextPath: File.EntryID
      description: The entry ID of the file.
      type: String
    - contextPath: File.Info
      description: File information.
      type: String
    - contextPath: File.Type
      description: The file type.
      type: String
    - contextPath: File.MD5
      description: The MD5 hash of the file.
      type: String
    - contextPath: File.Extension
      description: The file extension.
      type: String
    - contextPath: Securonix.Incidents.Attachments.IncidentID
      description: Attachment Incident ID.
      type: String
    - contextPath: Securonix.Incidents.Attachments.Files
      description: Attachment File names.
      type: Unknown
  - arguments:
    - description: "Name of the tenant the whitelist belongs to.\n\nThe tenant name parameter is required for MSSP users."
      name: tenant_name
    description: Gets a list of whitelists.
    name: securonix-whitelists-get
    outputs:
    - contextPath: Securonix.Whitelist.WhitelistName
      description: Name of the Whitelist.
      type: String
    - contextPath: Securonix.Whitelist.TenantName
      description: Tenant Name.
      type: String
    - contextPath: Securonix.Whitelist.WhitelistType
      description: Type of the Whitelist.
      type: String
  - arguments:
    - description: "Name of the tenant the whitelist belongs to.\n\nThe tenant name parameter is required for MSSP users."
      name: tenant_name
    - description: Name of the whitelist that the user wants to list.
      name: whitelist_name
      required: true
    description: Gets information for the specified whitelist.
    name: securonix-whitelist-entry-list
    outputs:
    - contextPath: Securonix.Whitelist.WhitelistName
      description: Name of the Whitelist.
      type: String
    - contextPath: Securonix.Whitelist.TenantName
      description: Tenant Name.
      type: String
    - contextPath: Securonix.Whitelist.Entries.Entity/Attribute
      description: Entity/Attribute which is whitelisted.
      type: String
    - contextPath: Securonix.Whitelist.Entries.ExpiryDate
      description: The date when the entity will be removed from the whitelist.
      type: Date
  - arguments:
    - description: "Name of the tenant the whitelist belongs to.\n\nThe tenant name parameter is required for MSSP users."
      name: tenant_name
    - description: Name of the whitelist that the user wants to create.
      name: whitelist_name
      required: true
    - auto: PREDEFINED
      description: Type of entity that the whitelist is intended to hold.
      name: entity_type
      predefined:
      - Users
      - Activityaccount
      - Resources
      - Activityip
      required: true
    description: Creates a whitelist in Securonix.
    name: securonix-whitelist-create
  - description: Returns the state mapping of XSOAR with Securonix.
    name: securonix-xsoar-state-mapping-get
    outputs:
    - contextPath: Securonix.StateMapping.ACTIVE.action
      description: Securonix action name to map with XSOAR's active state.
      type: String
    - contextPath: Securonix.StateMapping.ACTIVE.status
      description: Securonix status to map with XSOAR's active state.
      type: String
    - contextPath: Securonix.StateMapping.DONE.action
      description: Securonix action name to map with XSOAR's closed state.
      type: String
    - contextPath: Securonix.StateMapping.DONE.status
      description: Securonix status to map with XSOAR's closed state.
      type: String
  - arguments:
    - description: "The Name of the tenant the whitelist belongs to.\n\nThe tenant name parameter is required for MSSP user."
      name: tenant_name
    - description: "The name of the whitelist to which data is being added.\n\nIf whitelist_type is Attribute, then whitelist_name and violation_name should be the same."
      name: whitelist_name
      required: true
    - auto: PREDEFINED
      description: The type of the whitelist to which data is being added. (Supported Values are Global and Attribute.).
      name: whitelist_type
      predefined:
      - Global
      - Attribute
      required: true
    - auto: PREDEFINED
      description: "The type of entity being added. (Supported values are Users, Activityaccount, Activityip, Resources).\n\nThis parameter is required if whitelist_type is Global."
      name: entity_type
      predefined:
      - Users
      - Activityaccount
      - Resources
      - Activityip
    - description: "ID of the entity being added.\n\nThis parameter is required if whitelist_type is Global."
      name: entity_id
    - description: The date when the entity will be removed from the whitelist.(In MM/DD/YYYY format).
      name: expiry_date
    - description: "The resource name to which the account belongs. \n\nThis parameter is required if whitelist_type is Global and entity_type is Activityaccount."
      name: resource_name
    - description: "The resource group id to which the account belongs. \n\nThis parameter is required if whitelist_type is Global and entity_type is Activityaccount."
      name: resource_group_id
    - auto: PREDEFINED
      description: "Name of the attribute being added. (Supported values are source ip, resourcetype,\ntransactionstring)\n\nThis parameter is required if whitelist_type is Attribute."
      name: attribute_name
      predefined:
      - source ip
      - resourcetype
      - transactionstring
    - description: "The attribute value being added. \n\nThis parameter is required if whitelist_type is set to Attribute."
      name: attribute_value
    - auto: PREDEFINED
      description: "Type of the violation. (Supported Values are Policy,ThreatModel,\nFunctionality.) \n\nThis parameter is required if whitelist_type is set to Attribute."
      name: violation_type
      predefined:
      - Policy
      - ThreatModel
      - Functionality
    - description: "Name of the violations. (Supported values are Policy names, ThreatModel names, Functionality names)\n\nThis parameter is required if whitelist_type is set to Attribute, and is the same as the whitelist name parameter."
      name: violation_name
    description: Add entity or attribute to the specified whitelist entry.
    name: securonix-whitelist-entry-add
  - arguments:
    - description: Name of the lookup table to delete.
      name: name
      required: true
    description: Deletes a lookup table with its data and configuration.
    name: securonix-lookup-table-config-and-data-delete
    outputs:
    - contextPath: Securonix.LookupTable.lookupTableName
      description: Name of the lookup table.
      type: String
    - contextPath: Securonix.LookupTable.isDeleted
      description: True, if the lookup table data and configuration deleted successfully.
      type: Boolean
  - arguments:
    - description: Name of the tenant the whitelist belongs to.
      name: tenant_name
      required: true
    - description: Name of the whitelist the user wants to delete the value from.
      name: whitelist_name
      required: true
    - auto: PREDEFINED
      description: Type of whitelist that user wants to delete from.
      name: whitelist_type
      predefined:
      - Global
      - Attribute
    - description: "Entity ID value that needs to be removed from the whitelist.\n\nThis parameter is required if whitelist_type is set to \"Global\".\n\nExample:\n- employeeId for type User\n- accountname for type ActivityAccount\n- resourcename for type Resources\n- ipadress for type IpAddress."
      name: entity_id
    - description: "Name of the attribute being removed.\n\nThis parameter is required if whitelist_type is set to \"Attribute\".\n\nExample:\n- accountname\n- transactionstring\n- sourcetype."
      name: attribute_name
    - description: "The value of the attribute being removed.\n\nThis parameter is required if whitelist_type is \"Attribute\"."
      name: attribute_value
    description: Remove entity or attribute from the specified whitelist entry.
    name: securonix-whitelist-entry-delete
  - arguments:
    - defaultValue: '50'
      description: Number of records to return.
      name: max
    - defaultValue: '0'
      description: Specify from which record the data should be returned.
      name: offset
    description: Retrieves a list of lookup tables available within the Securonix platform.
    name: securonix-lookup-tables-list
    outputs:
    - contextPath: Securonix.LookupTable.tenantName
      description: Name of the tenant.
      type: String
    - contextPath: Securonix.LookupTable.lookupTableName
      description: Name of the lookup table.
      type: String
    - contextPath: Securonix.LookupTable.totalRecords
      description: Number of records in the lookup table.
      type: Number
    - contextPath: Securonix.LookupTable.scope
      description: Scope of the lookup table.
      type: String
    - contextPath: Securonix.LookupTable.type
      description: Type of the lookup table.
      type: String
  - arguments:
    - description: Lookup Table name to which the data needs to be added.
      name: name
      required: true
    - description: Name of the tenant to which the lookup table belongs. This argument is required for MSSP users and if the scope of the lookup table is "Meta".
      name: tenant_name
    - description: "JSON formatted string containing the field names and values in the below format. To specify an expiration date for an entry, add \"expiryDate\" key (in the format of \"MM/DD/YYYY\") in the respective JSON object.\n\nE.g. [{\"field1\": \"Value1\", \"field2\": \"Value2\"}, {\"field1\": \"Value3\", \"field2\": \"Value4\"}]."
      name: json_data
    - description: War room entry of the file. To specify an expiration date for an entry, add "expiryDate" key (in the format of "MM/DD/YYYY") in the respective JSON object.
      name: file_entry_id
    description: Add entries to the provided lookup table.
    name: securonix-lookup-table-entry-add
  - arguments:
    - description: Lookup Table name.
      name: name
      required: true
    - description: Use to filter the records. By default it will filter the records on key. To filter on other column use attribute argument.
      name: query
    - description: Column name on which to filter the data.
      name: attribute
      defaultValue: key
    - defaultValue: '15'
      description: Number of records to retrieve.
      name: max
    - description: Specify from which record the data should be returned.
      defaultValue: '0'
      name: offset
    - description: Specify a value to retrieve records from a specific page.
      name: page_num
      defaultValue: '1'
    - description: Name of the column on which to sort the data. By default the data will be sorted on the key.
      name: sort
    - auto: PREDEFINED
      defaultValue: asc
      description: The order in which to sort the data. By default the data will be sorted in ascending order.
      name: order
      predefined:
      - asc
      - desc
    description: Retrieves the entries stored in a specified lookup table.
    name: securonix-lookup-table-entries-list
    outputs:
    - contextPath: Securonix.LookupTableEntries.lookupname
      description: Name of the lookup table.
      type: String
    - contextPath: Securonix.LookupTableEntries.tenantid
      description: ID of the tenant.
      type: Number
    - contextPath: Securonix.LookupTableEntries.lookupuniquekey
      description: Unique key of the entry.
      type: String
    - contextPath: Securonix.LookupTableEntries.timestamp
      description: The UTC timestamp indicates when the entry was added.
      type: String
    - contextPath: Securonix.LookupTableEntries.key
      description: The value of the key field.
      type: String
    - contextPath: Securonix.LookupTableEntries.defaultenrichedevent
      description: Entry data.
      type: Unknown
    - contextPath: Securonix.LookupTableEntries.tenantname
      description: Name of the tenant.
      type: String
    - contextPath: Securonix.LookupTableEntries.entry.key
      description: Key of the entry.
      type: String
    - contextPath: Securonix.LookupTableEntries.entry.value
      description: Value of the entry.
      type: String
  - arguments:
    - description: Name of the lookup table to create.
      name: name
      required: true
    - auto: PREDEFINED
      description: Scope of the lookup table. This argument is mandatory for MSSP users.
      name: scope
      predefined:
      - Global
      - Local
      - Meta
    - description: Name of the tenant in which to create a lookup table. This argument is mandatory for MSSP users.
      name: tenant_name
    - description: A comma-separated string of column names.
      name: field_names
      required: true
    - description: A comma-separated string of column names for which data needs to be encrypted.
      name: encrypt
    - description: A comma-separated string of column names to be used as key.
      name: key
      required: true
    description: Creates a lookup table.
    name: securonix-lookup-table-create
  - arguments:
    - description: Comma-separated list of lookup unique keys to delete.
      name: lookup_unique_keys
      required: true
    - description: Name of the lookup table from which to delete the entries.
      name: name
      required: true
    description: Deletes the entries from the lookup table.
    name: securonix-lookup-table-entries-delete
  dockerimage: demisto/python3:3.12.12.5490952
  isfetch: true
  runonce: false
  script: >
    register_module_line('Securonix', 'start', __line__())

    CONSTANT_PACK_VERSION = '2.0.29'

    demisto.debug('pack id = Securonix, pack version = 2.0.29')

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



    def reformat_resource_groups_outputs(text: str) -> str:
        """rg_*text -> ResourceGroupText
        Args:
            text: the text to transform
        Returns:
            A Camel Cased string.
        """
        suffix = text[3:]
        if suffix == "id":
            suffix = "ID"
        elif suffix == "resourcetypeid":
            suffix = "TypeID"
        else:
            suffix = suffix.title()
        return f"ResourceGroup{suffix}"


    def reformat_outputs(text: str) -> str:
        """camelCase -> Camel Case, id -> ID
        Args:
            text: the text to transform
        Returns:
            A Demisto output standard string
        """
        if text.startswith("rg_"):
            return reformat_resource_groups_outputs(text)
        if text == "id":
            return "ID"
        if text in ["lanid", "u_lanid"]:
            return "LanID"
        if text == "jobId":
            return "JobID"
        if text == "eventId":
            return "EventID"
        if text in ["entityId", "entityid"]:
            return "EntityID"
        if text in ["tenantId", "tenantid"]:
            return "TenantID"
        if text == "incidentId":
            return "IncidentID"
        if text == "Datasourceid":
            return "DataSourceID"
        if text in ["employeeId", "employeeid", "u_employeeid"]:
            return "EmployeeID"
        if text == "violatorId":
            return "ViolatorID"
        if text == "threatname":
            return "ThreatName"
        if text == "generationtime":
            return "GenerationTime"
        if text == "generationtime_epoch":
            return "GenerationTime_Epoch"

        if text.startswith(("U_", "u_")):
            text = text[2:]
        return "".join(" " + char if char.isupper() else char.strip() for char in text).strip().title()


    def parse_data_arr(data_arr: Any, fields_to_drop: list = [], fields_to_include: list = []):
        """Parse data as received from Securonix into Demisto's conventions
        Args:
            data_arr: a dictionary containing the data
            fields_to_drop: Fields to drop from the array of the data
            fields_to_include: Fields to include from the array of the data
        Returns:
            A Camel Cased dictionary with the relevant fields.
            readable: for the human readable
            outputs: for the entry context
        """
        if isinstance(data_arr, list):
            readable_arr, outputs_arr = [], []
            for data in data_arr:
                readable = {reformat_outputs(i): j for i, j in data.items() if i not in fields_to_drop}
                if fields_to_include:
                    readable = {i: j for i, j in readable.items() if i in fields_to_include}
                readable_arr.append(readable)
                outputs_arr.append({k.replace(" ", ""): v for k, v in readable.copy().items()})
            return readable_arr, outputs_arr

        readable = {reformat_outputs(i): j for i, j in data_arr.items() if i not in fields_to_drop}
        if fields_to_include:
            readable = {i: j for i, j in readable.items() if i in fields_to_include}
        outputs = {k.replace(" ", ""): v for k, v in readable.copy().items()}

        return readable, outputs


    def string_escape_MD(data: Any):
        """
        Escape any chars that might break a markdown string.

        :type data: ``Any``
        :param data: The data to be modified (required).

        :return: A modified data.
        :rtype: ``str``
        """
        if isinstance(data, str):
            data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
        elif isinstance(data, list):
            new_data = []
            for sub_data in data:
                if isinstance(sub_data, str):
                    sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
                new_data.append(sub_data)
            data = new_data

        return data


    def incident_priority_to_dbot_score(priority_str: str, default_severity: str):
        """Converts an priority string to DBot score representation
            alert severity. Can be one of:
            Low    ->  1
            Medium ->  2
            High   ->  3

        Args:
            priority_str: String representation of priority.
            default_severity: Default incoming incident severity

        Returns:
            Dbot representation of severity
        """
        if default_severity:
            priority = default_severity.lower()
        else:
            priority = priority_str.lower()

        if priority == "low":
            return 1
        if priority == "medium":
            return 2
        if priority == "high":
            return 3
        demisto.info(f"Securonix incident priority: {priority} is not known. Setting as unknown(DBotScore of 0).")
        return 0


    def validate_configuration_parameters(params: dict[str, Any]):
        """
        Check whether entered configuration parameters are valid or not.

        :type: params: dict
        :param: Dictionary of demisto configuration parameter

        :return: raise ValueError if any configuration parameter is not in valid format else returns None
        :rtype: None
        """
        fetch_time = params.get("fetch_time")
        max_fetch = params.get("max_fetch")
        # Validate empty values
        if fetch_time is None:
            raise ValueError("Please provide First fetch time")
        if max_fetch is None:
            raise ValueError("Please provide max_fetch")
        # validate max_fetch
        arg_to_number(max_fetch, arg_name="max_fetch")
        # validate first_fetch parameter
        arg_to_datetime(fetch_time, "First fetch time")


    class RetryExponential(Retry):
        """
        Create wrapper of urllib3.util.retry for Add extra logs before making a retry request with exponential delay
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            diff = TOTAL_RETRY_COUNT - self.total  # type: ignore
            if 0 < diff <= TOTAL_RETRY_COUNT:
                demisto.debug(f"Performing retry {diff} with {self.get_backoff_time()} seconds delay for URL {FULL_URL}")


    class RetryFixed(Retry):
        """
        Create wrapper of urllib3.util.retry for Add extra logs before making a retry request with fixed delay
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            diff = TOTAL_RETRY_COUNT - self.total  # type: ignore
            if 0 < diff <= TOTAL_RETRY_COUNT:
                demisto.debug(f"Performing retry {diff} with {self.get_backoff_time()} seconds delay for URL {FULL_URL}.")

        # Overriding get_backoff_time logic for fixed backoff_factor
        def get_backoff_time(self) -> float:
            """
            Formula for computing the fixed backoff

            :rtype: float
            """
            consecutive_errors_len = len(list(takewhile(lambda x: x.redirect_location is None, reversed(self.history))))

            if consecutive_errors_len <= 1:
                return 0
            return min(self.DEFAULT_BACKOFF_MAX, int(self.backoff_factor))


    def validate_mirroring_parameters(params: dict[str, Any]) -> None:
        """Validate mirroring specific configuration parameters.

        Args:
            params: The integration configuration parameters got from demisto.params()
        """
        mirror_direction = params.get("mirror_direction", "None").strip()
        close_states_of_securonix = params.get("close_states_of_securonix", "").strip().lower()
        active_state_action = params.get("active_state_action_mapping", "").strip()
        active_state_status = params.get("active_state_status_mapping", "").strip().lower()
        close_state_action = params.get("closed_state_action_mapping", "").strip()
        close_state_status = params.get("closed_state_status_mapping", "").strip().lower()
        close_incident = argToBoolean(params.get("close_incident", False))
        comment_entry_tag = params.get("comment_tag", "").strip()

        if mirror_direction == "None":
            return

        if mirror_direction == "Incoming" and (not close_states_of_securonix or not argToList(close_states_of_securonix)):
            raise ValueError(
                'Following field is required for Incoming Mirroring: "Securonix workflow state(s) that '
                'can be considered as Close state in XSOAR for Incoming mirroring".'
            )

        if mirror_direction == "Outgoing" and (
            not active_state_action
            or not active_state_status
            or not close_state_action
            or not close_state_status
            or not comment_entry_tag
        ):
            raise ValueError(
                'Following fields are required for Outgoing Mirroring: "Securonix action name to map '
                'with XSOAR\'s active state for Outgoing mirroring", "Securonix status to map with '
                'XSOAR\'s active state for Outgoing mirroring", "Securonix action name to map with '
                "XSOAR's closed state for Outgoing mirroring\", \"Securonix status to map with XSOAR's "
                'closed state for Outgoing mirroring", "Comment Entry Tag".'
            )

        if mirror_direction == "Incoming And Outgoing" and (
            not active_state_action
            or not active_state_status
            or not close_state_action
            or not close_state_status
            or not close_states_of_securonix
            or not argToList(close_states_of_securonix)
            or not comment_entry_tag
        ):
            raise ValueError(
                'Following fields are required for Incoming And Outgoing Mirroring: "Securonix workflow '
                'state(s) that can be considered as Close state in XSOAR for Incoming mirroring", '
                '"Securonix action name to map with XSOAR\'s active state for Outgoing mirroring", '
                '"Securonix status to map with XSOAR\'s active state for Outgoing mirroring", "Securonix'
                ' action name to map with XSOAR\'s closed state for Outgoing mirroring", "Securonix status'
                ' to map with XSOAR\'s closed state for Outgoing mirroring", "Comment Entry Tag".'
            )

        if close_incident and not active_state_action or not active_state_status or not close_state_action or not close_state_status:
            raise ValueError(
                'Following fields are required for closing incident on Securonix: "Securonix action name '
                'to map with XSOAR\'s active state for Outgoing mirroring", "Securonix status to map '
                'with XSOAR\'s active state for Outgoing mirroring", "Securonix action name to map with '
                "XSOAR's closed state for Outgoing mirroring\", \"Securonix status to map with XSOAR's "
                'closed state for Outgoing mirroring".'
            )


    def validate_delete_whitelist_parameters(
        whitelist_type: str, entity_id: str, attribute_name: str, attribute_value: str, tenant_name: str
    ) -> None:
        """Validate parameters for delete whitelist entry command.

        Args:
            whitelist_type: Type of whitelist that user wants to delete from.
            entity_id: Entity ID value that needs to be removed from the whitelist.
            attribute_name: Name of the attribute being removed.
            attribute_value: The value of the attribute being removed.
            tenant_name: The name of the tenant the whitelist belongs to.

        Raises:
            ValueError: Raises ValueError if parameters are invalid.
        """
        # Validate whitelist_type parameter.
        if whitelist_type and whitelist_type not in VALID_WHITELIST_TYPE:
            raise ValueError(f"{whitelist_type} is an invalid value for whitelist_type.Valid whitelist types are {VALID_ENTITY_TYPE}")

        # Validate entity_id parameter.
        if whitelist_type == "Global" and not entity_id:
            raise ValueError("entity_id is required parameter for Global whitelist type.")

        # Validate attribute_name parameter.
        if whitelist_type == "Attribute" and not attribute_name:
            raise ValueError("attribute_name is required parameter for Attribute whitelist type.")

        # Validate attribute_value parameter.
        if whitelist_type == "Attribute" and not attribute_value:
            raise ValueError("attribute_value is required parameter for Attribute whitelist type.")

        # Validate tenant_name parameter.
        if not tenant_name:
            raise ValueError("tenant_name is a required parameter.")


    def get_mirroring() -> dict:
        """Add mirroring related keys in an incident.

        Returns:
            Dict: A dictionary containing required key-value pairs for mirroring.
        """
        # Fetch the integration configuration parameters to determine the flow of the mirroring and mirror tags.
        params = demisto.params()
        mirror_direction = params.get("mirror_direction", "None").strip()
        mirror_tags = params.get("comment_tag", "").strip()

        return {
            "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
            "mirror_instance": demisto.integrationInstance(),
            "mirror_tags": mirror_tags,
        }


    def filter_activity_entries_by_time(activity_data: list[dict[str, Any]], timestamp: int) -> list[dict[str, Any]]:
        """Filter the incident activity entries by the given timestamp.

        Args:
            activity_data (List[Dict[str, Any]]): A list of incident activity data.
            timestamp (int): The timestamp to filter the activity data.

        Returns:
            List[Dict[str, Any]]: Filtered incident activity entries.
        """
        filtered_activities = []

        for activity in activity_data:
            activity_timestamp = activity.get("eventTime", "")

            # If no event timestamp found in an entry, then skip that entry.
            if not activity_timestamp:
                demisto.debug(f"Skipping entry as no event timestamp found: {json.dumps(activity)}")
                continue

            if date_to_timestamp(parse(activity_timestamp)) >= timestamp:
                filtered_activities.append(activity)

        return filtered_activities


    def filter_comment_activity_entries(activity_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter the comment entries from the given incident activity entries.

        Args:
            activity_data (List[Dict[str, Any]]): A list of incident activity data.

        Returns:
            List[Dict[str, Any]]: Filtered comment entries from incident activity entries.
        """
        comment_entries = []

        for activity in activity_data:
            activity_action = activity.get("actiontaken", "")

            if activity_action == COMMENT_ACTION:
                comment_entries.append(activity)

        return comment_entries


    def filter_attachment_activity_entries(activity_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter the attachment entries from the given incident activity entries.

        Args:
            activity_data (List[Dict[str, Any]]): A list of incident activity data.

        Returns:
            List[Dict[str, Any]]: Filtered attachment entries from incident activity entries.
        """
        attachment_entries = []

        for activity in activity_data:
            activity_action = activity.get("actiontaken", "")

            if activity_action == ATTACHMENT_ACTION:
                attachment_entries.append(activity)

        return attachment_entries


    def extract_names_of_attachments_from_entries(attachment_entries: list[dict[str, Any]]) -> list[str]:
        """Return names of the attachments for a list of attachment entries.

        Args:
            attachment_entries (List[Dict[str, Any]]): A list of attachment entries.

        Returns:
            List[str]: A list of attachment names.
        """
        attachment_names = [attachment.get("attachment") for attachment in attachment_entries]

        # Remove any None values from the list and return it.
        return list(filter(None, attachment_names))


    def is_incident_closed_on_securonix(activity_data: list[dict[str, Any]], close_states_of_securonix: list[str]) -> bool:
        """Check whether the incident is closed on the Securonix.

        Args:
            activity_data: A list of activity data from which to determine whether the incident is closed or not.
            close_states_of_securonix: A list of Securonix states which defines the close state for XSOAR.

        Returns:
            bool: Indicating whether the incident is closed on Securonix or not.
        """
        incident_closed = []

        for activity in activity_data:
            current_status = activity.get("status", "").strip().lower()
            last_status = activity.get("lastStatus", "").strip().lower()

            if current_status != last_status and current_status in close_states_of_securonix:
                incident_closed.append(True)
            else:
                incident_closed.append(False)

        return any(incident_closed)


    def extract_closing_comments(activity_data: list[dict[str, Any]], close_states_of_securonix: list[str]) -> str:
        """Extract the contents of the closing comments from activity data provided from Securonix.

        Args:
            activity_data: A list of activity data from which to extract the closing comments.
            close_states_of_securonix: A list of Securonix states which defines the close state for XSOAR.

        Returns:
            str: A string representing closing comments.
        """
        closing_comments = []

        for activity in activity_data:
            current_status = activity.get("status", "").strip().lower()
            last_status = activity.get("lastStatus", "").strip().lower()

            if current_status != last_status and current_status in close_states_of_securonix:
                comments_list = activity.get("comment", [])

                for _comment in comments_list:
                    closing_comments.append(_comment.get("Comments", ""))

        if not closing_comments:
            closing_comments.append("Closing the XSOAR incident as Securonix incident is closed.")

        return " | ".join(closing_comments)


    def escape_spotter_query(original_query: str) -> str:
        """Escape the special characters of the spotter query provided from Securonix Incident.

        Args:
            original_query: The original spotter query provided from Securonix Incident

        Returns:
            str: The spotter query escaped for special characters.
        """
        escaped_query = original_query
        for special_char in SPOTTER_SPECIAL_CHARACTERS:
            escaped_query = escaped_query.replace(special_char, f"\\{special_char}")
        return escaped_query


    class Client(BaseClient):
        """
        Client to use in the Securonix integration. Overrides BaseClient
        """

        def __init__(
            self,
            tenant: str,
            server_url: str,
            username: str,
            password: str,
            verify: bool,
            proxy: bool,
            securonix_retry_count: int,
            securonix_retry_delay: int,
            securonix_retry_delay_type: str,
        ):
            super().__init__(base_url=server_url, verify=verify, proxy=proxy)
            self._username = username
            self._password = password
            self._tenant = tenant
            self._securonix_retry_count = securonix_retry_count
            self._securonix_retry_delay = securonix_retry_delay
            self._securonix_retry_delay_type = securonix_retry_delay_type
            self.session = requests.Session()

            # Fetch cached integration context.
            integration_context = get_integration_context()
            self._token = integration_context.get("token") or self._generate_token()

            # the following condition was added to overcome the security hardening happened in Python 3.10.
            # https://github.com/python/cpython/pull/25778
            # https://bugs.python.org/issue43998

            if IS_PY3 and PY_VER_MINOR >= 10 and not verify:
                self.session.mount("https://", SSLAdapter(verify=verify))

        def get_securonix_retry_count(self):
            return self._securonix_retry_count

        def get_securonix_retry_delay(self):
            return self._securonix_retry_delay

        def get_securonix_retry_delay_type(self):
            return self._securonix_retry_delay_type

        def implement_retry(
            self,
            retries: int = 0,
            status_list_to_retry: list = None,
            backoff_factor: int = 30,
            raise_on_redirect: bool = False,
            raise_on_status: bool = False,
        ):
            """
            Implements the retry mechanism.
            In the default case where retries = 0 the request will fail on the first time

            :type retries: ``int`` :param retries: How many retries should be made in case of a failure. when set to '0'-
            will fail on the first time

            :type status_list_to_retry: ``iterable``
            :param status_list_to_retry: A set of integer HTTP status codes that we should force a retry on.
                A retry is initiated if the request method is in ['GET', 'POST', 'PUT']
                and the response status code is in ``status_list_to_retry``.

            :type backoff_factor ``float``
            :param backoff_factor:
                A backoff factor to apply between attempts after the second try
                (most errors are resolved immediately by a second try without a
                delay). urllib3 will sleep for::

                    {backoff factor} * (2 ** ({number of total retries} - 1))

                seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep
                for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer
                than :attr:`Retry.BACKOFF_MAX`.

                By default, backoff_factor set to 5

            :type raise_on_redirect ``bool``
            :param raise_on_redirect: Whether, if the number of redirects is
                exhausted, to raise a MaxRetryError, or to return a response with a
                response code in the 3xx range.

            :type raise_on_status ``bool``
            :param raise_on_status: Similar meaning to ``raise_on_redirect``:
                whether we should raise an exception, or return a response,
                if status falls in ``status_forcelist`` range and retries have
                been exhausted.
            """
            try:
                method_whitelist = (
                    "allowed_methods"
                    if hasattr(
                        Retry.DEFAULT,  # type: ignore[attr-defined]
                        "allowed_methods",
                    )
                    else "method_whitelist"
                )
                whitelist_kawargs = {method_whitelist: frozenset(["GET", "POST", "PUT"])}
                retry = None
                if self._securonix_retry_delay_type == "Fixed":
                    demisto.debug("Securonix Retry delay type is Fixed")
                    # Set DEFAULT_BACKOFF_MAX to 2hour(in seconds)
                    RetryFixed.DEFAULT_BACKOFF_MAX = 7200
                    retry = RetryFixed(
                        total=retries,
                        connect=0,
                        read=0,
                        backoff_factor=backoff_factor,
                        status=retries,
                        status_forcelist=status_list_to_retry,
                        raise_on_status=raise_on_status,
                        raise_on_redirect=raise_on_redirect,
                        **whitelist_kawargs,  # type: ignore[arg-type]
                    )
                else:
                    demisto.debug("Securonix Retry delay type is Exponential")
                    # Set DEFAULT_BACKOFF_MAX to 2hour(in seconds)
                    RetryExponential.DEFAULT_BACKOFF_MAX = 7200
                    retry = RetryExponential(  # type: ignore
                        total=retries,
                        backoff_factor=backoff_factor,
                        connect=0,
                        read=0,
                        status=retries,
                        status_forcelist=status_list_to_retry,
                        raise_on_status=raise_on_status,
                        raise_on_redirect=raise_on_redirect,
                        **whitelist_kawargs,  # type: ignore[arg-type]
                    )
                http_adapter = HTTPAdapter(max_retries=retry)

                # the following condition was added to overcome the security hardening happened in Python 3.10.
                # https://github.com/python/cpython/pull/25778
                # https://bugs.python.org/issue43998

                if self._verify:
                    https_adapter = http_adapter
                elif IS_PY3 and PY_VER_MINOR >= 10:
                    https_adapter = SSLAdapter(max_retries=retry, verify=self._verify)  # type: ignore[arg-type]
                else:
                    https_adapter = http_adapter

                self.session.mount("https://", https_adapter)

            except NameError:
                pass

        def http_request(
            self,
            method,
            url_suffix,
            headers=None,
            params=None,
            response_type: str = "json",
            json=None,
            data=None,
            regenerate_access_token=True,
        ):
            """
            Generic request to Securonix
            """
            global FULL_URL
            FULL_URL = urljoin(self._base_url, url_suffix)
            status_list_to_retry = [429] + list(range(500, 600))
            if self._securonix_retry_count > 0:
                self.implement_retry(
                    retries=self._securonix_retry_count,
                    status_list_to_retry=status_list_to_retry,
                    backoff_factor=self._securonix_retry_delay,
                    raise_on_redirect=False,
                    raise_on_status=True,
                )

            try:
                demisto.debug(f"Making HTTP request with URL {FULL_URL}")
                result = self.session.request(
                    method,
                    FULL_URL,
                    params=params,
                    headers=headers,
                    verify=self._verify,
                    json=json,
                    data=data,
                )
                if result.status_code == 403 and regenerate_access_token:
                    self._token = self._generate_token()
                    headers["token"] = self._token
                    return self.http_request(method, url_suffix, headers, params, response_type, json, data, False)
                if not result.ok:
                    raise ValueError(f"Error in API call to Securonix {result.status_code}. Reason: {result.text}")
                try:
                    if url_suffix == "/incident/attachments":
                        return result
                    if response_type != "json":
                        return result.text
                    return result.json()
                except Exception:
                    raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{result.text}")

            except requests.exceptions.ConnectTimeout as exception:
                err_msg = (
                    "Connection Timeout Error - potential reasons might be that the Server URL parameter"
                    " is incorrect or that the Server is not accessible from your host."
                )
                raise Exception(f"{err_msg}\n{exception}")

            except requests.exceptions.SSLError as exception:
                err_msg = (
                    "SSL Certificate Verification Failed - try selecting 'Trust any certificate' checkbox in"
                    " the integration configuration."
                )
                raise Exception(f"{err_msg}\n{exception}")

            except requests.exceptions.ProxyError as exception:
                err_msg = (
                    "Proxy Error - if the 'Use system proxy' checkbox in the integration configuration is"
                    " selected, try clearing the checkbox."
                )
                raise Exception(f"{err_msg}\n{exception}")

            except requests.exceptions.ConnectionError as exception:
                error_class = str(exception.__class__)
                err_type = "<" + error_class[error_class.find("'") + 1 : error_class.rfind("'")] + ">"  # noqa: E203
                err_msg = (
                    f"Error Type: {err_type}\n"
                    f"Error Number: [{exception.errno}]\n"
                    f"Message: {exception.strerror}\n"
                    f"Verify that the tenant parameter is correct "
                    f"and that you have access to the server from your host."
                )
                raise Exception(f"{err_msg}\n{exception}")

            except requests.exceptions.RetryError as exception:
                try:
                    reason = f"Reason: {exception.args[0].reason.args[0]}"  # pylint: disable=no-member
                except Exception:  # noqa: disable=broad-except
                    reason = ""
                err_msg = (
                    f"Max Retries Error: Request attempts with {self._securonix_retry_count} retries and with "
                    f"{self._securonix_retry_delay} seconds {self._securonix_retry_delay_type} delay "
                    f"failed.\n{reason}"
                )
                if self._securonix_retry_delay_type == "Exponential":
                    # For Exponential delay we are dividing it by 2 so for error message make it to original value
                    err_msg = (
                        f"Max Retries Error: Request attempts with {self._securonix_retry_count} retries and with"
                        f" {self._securonix_retry_delay * 2} seconds {self._securonix_retry_delay_type} delay "
                        f"failed.\n{reason}"
                    )
                demisto.error(err_msg)
                raise Exception(f"{err_msg}\n{exception}")

            except requests.exceptions.InvalidHeader as exception:
                set_integration_context({})
                raise Exception(f"Invalid token generated from the API.\n{exception}")

            except Exception as exception:
                raise Exception(str(exception))

        def _generate_token(self) -> str:
            """Generate a token

            Returns:
                token valid for 1 day
            """
            demisto.info("Generating new access token.")
            headers = {
                "username": self._username,
                "password": self._password,
                "validity": "1",
            }
            token = self.http_request("GET", "/token/generate", headers=headers, response_type="text")

            set_integration_context({"token": token})
            return token

        def list_workflows_request(self) -> dict:
            """List workflows.

            Returns:
                Response from API.
            """
            workflows = self.http_request("GET", "/incident/get", headers={"token": self._token}, params={"type": "workflows"})
            return workflows.get("result").get("workflows")

        def get_default_assignee_for_workflow_request(self, workflow: str) -> dict:
            """Get default assignee for a workflow..

            Args:
                workflow: workflow name

            Returns:
                Response from API.
            """
            params = {"type": "defaultAssignee", "workflow": workflow}
            default_assignee = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
            return default_assignee.get("result")

        def list_possible_threat_actions_request(self) -> dict:
            """List possible threat actions.

            Returns:
                Response from API.
            """

            threat_actions = self.http_request(
                "GET", "/incident/get", headers={"token": self._token}, params={"type": "threatActions"}
            )
            return threat_actions.get("result")

        def list_policies_request(self) -> dict:
            """List policies.

            Returns:
                Response from API.
            """

            policies = self.http_request("GET", "/policy/getAllPolicies", headers={"token": self._token}, response_type="xml")
            return policies

        def list_resource_groups_request(self) -> dict:
            """List resource groups.

            Returns:
                Response from API.
            """

            resource_groups = self.http_request("GET", "/list/resourceGroups", headers={"token": self._token}, response_type="xml")
            return resource_groups

        def list_users_request(self) -> dict:
            """List users.

            Returns:
                Response from API.
            """

            users = self.http_request("GET", "/list/allUsers", headers={"token": self._token}, response_type="xml")
            return users

        def list_activity_data_request(self, from_: str, to_: str, query: str = None, max_records: int = None) -> dict:
            """List activity data.

            Args:
                from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
                to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
                query: open query.
                max_records: maximum number of activity records to retrieve.

            Returns:
                Response from API.
            """
            params = {"query": "index=activity", "eventtime_from": from_, "eventtime_to": to_, "prettyJson": True}
            if max_records is not None:
                params["max"] = max_records
            remove_nulls_from_dictionary(params)
            if query:
                if re.findall(r"index\s*=\s*\w+", query):
                    params["query"] = query
                else:
                    params["query"] = f"{params['query']} AND {query}"
            activity_data = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
            return activity_data

        def list_violation_data_request(
            self, from_: str, to_: str, query: str = None, query_id: str = None, max_violations: int | None = 1000
        ) -> dict:
            """List violation data.

            Args:
                from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
                to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
                query: open query.
                query_id: query_id to paginate violations.
                max_violations: max number of violations to return.

            Returns:
                Response from API.
            """
            params = {
                "query": "index=violation",
                "generationtime_from": from_,
                "generationtime_to": to_,
                "queryId": query_id,
                "prettyJson": True,
                "max": max_violations,
            }
            if query:
                if re.findall(r"index\s*=\s*\w+", query):
                    params["query"] = query
                else:
                    params["query"] = f"{params['query']} AND {query}"

            remove_nulls_from_dictionary(params)
            violation_data = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
            return violation_data

        def list_incidents_request(
            self, from_epoch: str, to_epoch: str, incident_status: str, max_incidents: str = "200", offset: str = "0"
        ) -> dict:
            """List all incidents by sending a GET request.

            Args:
                from_epoch: from time in epoch
                to_epoch: to time in epoch
                incident_status: incident status e.g:closed, opened
                max_incidents: max incidents to get
                offset: offset to be used

            Returns:
                Response from API.
            """
            headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v6.0+json"}
            params = {
                "type": "list",
                "from": from_epoch,
                "to": to_epoch,
                "rangeType": incident_status,
                "max": max_incidents,
                "order": "asc",
                "offset": offset,
            }
            incidents = self.http_request("GET", "/incident/get", headers=headers, params=params)
            return incidents.get("result").get("data")

        def get_incident_request(self, incident_id: str) -> dict:
            """get incident meta data by sending a GET request.

            Args:
                incident_id: incident ID.

            Returns:
                Response from API.
            """
            headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v6.0+json"}
            params = {
                "type": "metaInfo",
                "incidentId": incident_id,
            }
            incident = self.http_request("GET", "/incident/get", headers=headers, params=params)
            return incident.get("result").get("data")

        def get_incident_status_request(self, incident_id: str) -> dict:
            """get incident meta data by sending a GET request.

            Args:
                incident_id: incident ID.

            Returns:
                Response from API.
            """
            params = {
                "type": "status",
                "incidentId": incident_id,
            }
            incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
            return incident.get("result")

        def get_incident_workflow_request(self, incident_id: str) -> dict:
            """get incident workflow by sending a GET request.

            Args:
                incident_id: incident ID.

            Returns:
                Response from API.
            """
            params = {
                "type": "workflow",
                "incidentId": incident_id,
            }
            incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
            return incident.get("result")

        def get_incident_available_actions_request(self, incident_id: str) -> dict:
            """get incident available actions by sending a GET request.

            Args:
                incident_id: incident ID.

            Returns:
                Response from API.
            """
            params = {
                "type": "actions",
                "incidentId": incident_id,
            }
            incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
            return incident.get("result")

        def get_incident_attachments_request(
            self, incident_id, attachment_type: str = None, attachment_from: int = None, attachment_to: int = None
        ):
            """Get incident attachments by sending a GET request.

            Args:
                incident_id: Incident ID.
                attachment_type: The type of attachment to retrieve. Supported options are
                csv, pdf, and txt. Comma-separated values are supported.
                attachment_from: Start time for which to retrieve attachments. (in the format YYYY-MM-DDTHH:MM:SS format)
                attachment_to: End time for which to retrieve attachments. (in the in the format YYYY-MM-DDTHH:MM:SS format)
                format)

            Returns:
                Response from API.
            """
            params = {
                "incidentId": incident_id,
                "attachmenttype": attachment_type,
                "datefrom": attachment_from,
                "dateto": attachment_to,
            }
            remove_nulls_from_dictionary(params)
            attachment_res = self.http_request("GET", "/incident/attachments", headers={"token": self._token}, params=params)
            return attachment_res

        def perform_action_on_incident_request(self, incident_id, action: str, action_parameters: str) -> dict:
            """get incident available actions by sending a GET request.

            Args:
                incident_id: incident ID.
                action: action to perform on the incident.
                action_parameters: parameters needed in order to perform the action.

            Returns:
                Response from API.
            """

            params = {"type": "actionInfo", "incidentId": incident_id, "actionName": action}
            if action_parameters:
                action_parameters_dict = {k: v.strip('"') for k, v in [i.split("=", 1) for i in action_parameters.split(",")]}
                params.update(action_parameters_dict)

            possible_action = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)

            if "error" in possible_action:
                err_msg = possible_action.get("error")
                raise Exception(
                    f"Failed to perform the action {action} on incident {incident_id}.\nError from Securonix is: {err_msg}"
                )

            incident = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
            return incident.get("result")

        def add_comment_to_incident_request(self, incident_id: str, comment: str) -> dict:
            """add comment to an incident by sending a POST request.

            Args:
                incident_id: incident ID.
                comment: action to perform on the incident

            Returns:
                Response from API.
            """
            params = {"incidentId": incident_id, "comment": comment, "actionName": "comment"}
            incident = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
            return incident.get("result")

        def create_incident_request(
            self,
            violation_name: str,
            resource_group: str,
            resource_name: str,
            entity_type: str,
            entity_name: str,
            action_name: str,
            workflow: str = None,
            comment: str = None,
            criticality: str = None,
        ) -> dict:
            """create an incident by sending a POST request.

            Args:
                violation_name: violation or policy name.
                resource_group: resource group name.
                resource_name: resource name.
                entity_type: entity type.
                entity_name: entity name.
                action_name: action name.
                workflow: workflow name.
                comment: comment on the incident.
                criticality: criticality for the incident.

            Returns:
                Response from API.
            """
            params = {
                "violationName": violation_name,
                "datasourceName": resource_group,
                "resourceName": resource_name,
                "entityType": entity_type,
                "entityName": entity_name,
                "actionName": action_name,
            }
            if workflow:
                params["workflow"] = workflow
            if comment:
                params["comment"] = comment
            if criticality:
                params["criticality"] = criticality

            response = self.http_request("POST", "/incident/actions", headers={"token": self._token}, params=params)
            return response

        def list_watchlist_request(self):
            """list watchlists by sending a GET request.

            Returns:
                Response from API.
            """
            watchlists = self.http_request("GET", "/incident/listWatchlist", headers={"token": self._token})
            return watchlists.get("result")

        def get_watchlist_request(self, watchlist_name: str) -> dict:
            """Get a watchlist by sending a GET request.

            Args:
                watchlist_name: watchlist name.

            Returns:
                Response from API.
            """
            params = {
                "query": f'index=watchlist AND watchlistname="{watchlist_name}"',
            }
            watchlist = self.http_request("GET", "/spotter/index/search", headers={"token": self._token}, params=params)
            return watchlist

        def create_watchlist_request(self, watchlist_name: str, tenant_name: str) -> dict:
            """Create a watchlist by sending a POST request.

            Args:
                watchlist_name: watchlist name.
                tenant_name: Name of the tenant the watchlist belongs to.

            Returns:
                Response from API.
            """
            params = {"watchlistname": watchlist_name, "tenantname": tenant_name}
            remove_nulls_from_dictionary(params)
            watchlist = self.http_request(
                "POST", "/incident/createWatchlist", headers={"token": self._token}, params=params, response_type="text"
            )
            return watchlist

        def check_entity_in_watchlist_request(self, entity_name: str, watchlist_name: str) -> dict:
            """Check if an entity is whitelisted by sending a GET request.

            Args:
                entity_name: Entity name.
                watchlist_name: Watchlist name.

            Returns:
                Response from API.
            """
            params = {"entityId": entity_name, "watchlistname": watchlist_name}
            response = self.http_request("GET", "/incident/checkIfWatchlisted", headers={"token": self._token}, params=params)
            return response

        def add_entity_to_watchlist_request(self, watchlist_name: str, entity_type: str, entity_name: str, expiry_days: str) -> dict:
            """Check if an entity is whitelisted by sending a GET request.

            Args:
                watchlist_name: Watchlist name.
                entity_type: Entity type.
                entity_name: Entity name.
                expiry_days: Expiry in days.
            Returns:
                Response from API.
            """
            params = {
                "watchlistname": watchlist_name,
                "entityType": entity_type,
                "entityId": entity_name,
                "expirydays": expiry_days,
                "resourcegroupid": "-1",
            }
            watchlist = self.http_request(
                "POST", "/incident/addToWatchlist", headers={"token": self._token}, params=params, response_type="txt"
            )
            return watchlist

        def list_threats_request(
            self, from_epoch: int, to_epoch: int, tenant_name: str, offset: int = 0, max_incidents: int = 10
        ) -> dict:
            """List all threats by sending a GET request.

            Args:
                from_epoch: from time in epoch
                to_epoch: to time in epoch
                tenant_name: tenant name
                offset: A page number to fetch from
                max_incidents: max incidents to get

            Returns:
                Response from API.
            """
            params = {
                "datefrom": from_epoch,
                "dateto": to_epoch,
                "tenantname": tenant_name,
                "max": max_incidents,
                "offset": offset,
            }
            headers = {"token": self._token, "Accept": "application/vnd.snypr.app-v1.0+json"}

            remove_nulls_from_dictionary(params)
            response = self.http_request("GET", "/sccWidget/getThreats", headers=headers, params=params)
            return response.get("Response", {}).get("threats", {})

        def get_incident_activity_history_request(self, incident_id: str) -> list:
            """Get incident activity history by sending a GET request.

            Args:
                incident_id (str): Incident ID for which to retrieve the activity history.

            Returns:
                Response from API.
            """
            params = {
                "type": "activityStreamInfo",
                "incidentId": incident_id,
            }
            incident = self.http_request("GET", "/incident/get", headers={"token": self._token}, params=params)
            return incident.get("result", {}).get("activityStreamData", [])

        def list_whitelists_request(self, tenant_name: str) -> list:
            """Get a whitelist information by sending a GET request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.

            Returns:
                Response from API.
            """
            params = {"tenantname": tenant_name}
            remove_nulls_from_dictionary(params)
            whitelist = self.http_request("GET", "/incident/getlistofWhitelist", headers={"token": self._token}, params=params)
            return whitelist.get("result", [])

        def get_whitelist_entry_request(self, tenant_name: str, whitelist_name: str) -> dict:
            """Get a whitelist information by sending a GET request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.
                whitelist_name: Name of the whitelist.

            Returns:
                Response from API.
            """
            params = {"tenantname": tenant_name, "whitelistname": whitelist_name}
            remove_nulls_from_dictionary(params)
            whitelist = self.http_request("GET", "/incident/listWhitelistEntities", headers={"token": self._token}, params=params)
            return whitelist.get("result", {})

        def add_whitelist_entry_request(
            self,
            tenant_name: str,
            whitelist_name: str,
            whitelist_type: str,
            entity_type: str,
            entity_id: str,
            expiry_date: str,
            resource_name: str,
            resource_group_id: str,
            attribute_name: str,
            attribute_value: str,
            violation_type: str,
            violation_name: str,
        ):
            """Add entry in whitelist by sending a POST request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.
                whitelist_name: Name of the whitelist.
                whitelist_type: Type of the whitelist.
                entity_type: Entity Type is required if whitelist is global.
                entity_id: Entity ID is required if whitelist is global.
                expiry_date: Expiry Date in format(MM/DD/YYYY).
                resource_name: Resource name which the account belongs to.
                resource_group_id: Resource Group ID which the account belongs to.
                attribute_name: Attribute name.
                attribute_value: Attribute Value.
                violation_type: Violation Type.
                violation_name: Violation Name.

            Returns:
                Response from API.
            """
            params = {
                "tenantname": tenant_name,
                "whitelistname": whitelist_name,
                "whitelisttype": whitelist_type,
                "entitytype": entity_type,
                "entityid": entity_id,
                "expirydate": expiry_date,
                "resourcename": resource_name,
                "resourcegroupid": resource_group_id,
                "attributename": attribute_name,
                "attributevalue": attribute_value,
                "violationtype": violation_type,
                "violationname": violation_name,
            }
            remove_nulls_from_dictionary(params)
            response = self.http_request("POST", "/incident/addToWhitelist", headers={"token": self._token}, params=params)
            return response

        def create_whitelist_request(self, tenant_name: str, whitelist_name: str, entity_type: str) -> dict:
            """Create a whitelist by sending a POST request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.
                whitelist_name: Name of the whitelist.
                entity_type: Type of entity that the whitelist is intended to hold.

            Returns:
                Response from API.
            """
            params = {"tenantname": tenant_name, "whitelistname": whitelist_name, "entitytype": entity_type}
            remove_nulls_from_dictionary(params)
            whitelist = self.http_request("POST", "/incident/createGlobalWhitelist", headers={"token": self._token}, params=params)
            return whitelist

        def delete_whitelist_entry_request(
            self,
            tenant_name: str,
            whitelist_name: str,
            whitelist_type: str,
            entity_id: str,
            attribute_name: str,
            attribute_value: str,
        ) -> dict:
            """Delete a whitelist entry by sending POST request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.
                whitelist_name: Name of the whitelist.
                whitelist_type: Type of whitelist that user wants to delete from.
                entity_id: Entity ID value that needs to be removed from the whitelist.
                attribute_name: Name of the attribute being removed.
                attribute_value: The value of the attribute being removed.

            Returns:
                Response from API.
            """
            params = {
                "tenantname": tenant_name,
                "whitelistname": whitelist_name,
                "whitelisttype": whitelist_type,
                "entityid": entity_id,
                "attributename": attribute_name,
                "attributevalue": attribute_value,
            }
            remove_nulls_from_dictionary(params)
            return self.http_request("GET", "/incident/removeFromWhitelist", headers={"token": self._token}, params=params)

        def delete_lookup_table_config_and_data_request(self, name: str) -> str:
            """Delete a lookup table and its configuration data from Securonix.

            Args:
                name (str): Name of the lookup table.

            Returns:
                str: Response from API.
            """
            params = {"lookupTableName": name}
            return self.http_request(
                "DELETE",
                "/lookupTable/deleteLookupConfigAndData",
                headers={"token": self._token},
                params=params,
                response_type="text",
            )

        def get_lookup_tables_request(self, max_records: int | None = 50, offset: int | None = 0) -> list:
            """Get the list of lookup tables stored on the Securonix platform.

            Args:
                max_records (Optional[int]): Number of records to return. Default value is 50.
                offset (Optional[int]): Specify from which record the data should be returned.

            Returns:
                Response from API.
            """
            params = {"max": max_records, "offset": offset}
            return self.http_request("GET", "/lookupTable/listLookupTables", headers={"token": self._token}, params=params)

        def add_entry_to_lookup_table_request(self, name: str, entries: list[dict], tenant_name: str | None = None) -> str:
            """Adds the provided entries to the specified lookup table.

            Args:
                name (str): Name of the lookup table in which to add the data.
                entries (List[Dict]): List of entries to add to the table.
                tenant_name (Optional[str]): Tenant name to which the lookup table belongs to.
            """
            body = {"lookupTableName": name, "tenantName": tenant_name, "lookupTableData": entries}
            remove_nulls_from_dictionary(body)
            return self.http_request(
                "POST", "/lookupTable/addLookupTableData", headers={"token": self._token}, json=body, response_type="text"
            )

        def list_lookup_table_entries_request(
            self,
            name: str,
            query: str | None = None,
            attribute: str | None = "key",
            max_records: int | None = 15,
            offset: int | None = 0,
            page_num: int | None = 1,
            sort: str | None = None,
            order: str | None = "asc",
        ) -> list:
            """List the entries of the lookup table.

            Args:
                name (str): Name of the lookup table.
                query (Optional[str], optional): Query to filter the entries of the lookup table. Defaults to None.
                attribute (Optional[str], optional): Column name on which to filter the data. Defaults to 'key'.
                max_records (Optional[int], optional): Number of records to retrieve. Defaults to 15.
                offset (Optional[int], optional): Specify from which record the data should be returned. Defaults to 0.
                page_num (Optional[int], optional): Specify a value to retrieve the records from a specified page.
                    Defaults to 1.
                sort (Optional[str]): Name of the column on which to sort the data.
                order (Optional[str]): The order in which to sort the data.

            Returns:
                List: List of lookup table entries.
            """
            headers = {"token": self._token, "Content-Type": "application/json"}

            body = {
                "lookupTableName": name,
                "query": query,
                "attribute": attribute,
                "max": max_records,
                "offset": offset,
                "pagenum": page_num,
                "sort": sort,
                "order": order,
            }
            remove_nulls_from_dictionary(body)
            payload = json.dumps(body)

            return self.http_request("GET", "/lookupTable/getLookupTableData", headers=headers, data=payload)

        def create_lookup_table_request(
            self, tenant_name: str, name: str, scope: str, field_names: list, encrypt: list, key: list
        ) -> dict:
            """Create a lookup table by sending a POST request.

            Args:
                tenant_name: Name of the tenant the whitelist belongs to.
                name: Lookup table name.
                scope: Scope of lookup table.
                field_names: Field names for lookup table.
                encrypt: Field name which data needs to be encrypted.
                key: Field name to be used as key.

            Returns:
                Response from API.
            """
            data: dict[str, Any] = {"lookupTableName": name, "lookupTableScope": scope, "tenantName": tenant_name}
            field_list: list = []
            for field in field_names:
                field_dic = {"fieldName": field, "encrypt": field in encrypt, "key": field in key}
                field_list.append(field_dic)
            data.update({"lookupFieldList": field_list})
            remove_nulls_from_dictionary(data)
            response = self.http_request(
                "POST", "/lookupTable/createLookupTable", headers={"token": self._token}, json=data, response_type="text"
            )
            return response

        def delete_lookup_table_entries(self, name: str, lookup_unique_keys: list[str]) -> str:
            """Delete entries from the lookup table.

            Args:
                name (str): Name of the lookup table.
                lookup_unique_keys (List[str]): List of keys to delete from the lookup table.

            Returns:
                str: Response from API.
            """
            data: dict[str, Any] = {"lookupTableName": name, "keyList": lookup_unique_keys}
            response = self.http_request(
                "DELETE", "/lookupTable/deleteLookupKeys", headers={"token": self._token}, json=data, response_type="text"
            )
            return response


    def test_module(client: Client) -> str:
        """
        Performs basic get request to get incident samples
        """
        params = demisto.params()
        client.list_workflows_request()

        if params.get("isFetch"):
            validate_configuration_parameters(params)
            validate_mirroring_parameters(params=params)

            timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
            from_epoch = date_to_timestamp(parse_date_range("1 day", utc=True)[0], date_format=timestamp_format)
            to_epoch = date_to_timestamp(datetime.now(), date_format=timestamp_format)
            client.list_incidents_request(from_epoch, to_epoch, incident_status="opened")

        return "ok"


    def list_workflows(client: Client, *_) -> tuple[str, dict, dict]:
        """List all workflows.

        Args:
            client: Client object with request.
            *_:

        Returns:
            Outputs.
        """
        workflows = client.list_workflows_request()
        workflows_readable, workflows_outputs = parse_data_arr(workflows)
        human_readable = tableToMarkdown(
            name="Available workflows:", t=workflows_readable, headers=["Workflow", "Type", "Value"], removeNull=True
        )
        entry_context = {"Securonix.Workflows(val.Workflow == obj.Workflow)": workflows_outputs}
        return human_readable, entry_context, workflows


    def get_default_assignee_for_workflow(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Perform action on an incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        workflow = str(args.get("workflow"))
        default_assignee = client.get_default_assignee_for_workflow_request(workflow)
        workflow_output = {
            "Workflow": workflow,
            "Type": default_assignee.get("type"),
            "Value": default_assignee.get("value"),
        }
        entry_context = {"Securonix.Workflows(val.Workflow === obj.Workflow)": workflow_output}
        human_readable = f"Default assignee for the workflow {workflow} is: {default_assignee.get('value')}."
        return human_readable, entry_context, default_assignee


    def list_possible_threat_actions(client: Client, *_) -> tuple[str, dict, dict]:
        """List all workflows.

        Args:
            client: Client object with request.
            *_:

        Returns:
            Outputs.
        """
        threat_actions = client.list_possible_threat_actions_request()
        human_readable = f"Possible threat actions are: {', '.join(threat_actions)}."
        entry_context = {"Securonix.ThreatActions": threat_actions}
        return human_readable, entry_context, threat_actions


    def list_policies(client: Client, *_) -> tuple[str, dict, dict]:
        """List all policies.

        Args:
            client: Client object with request.
            *_:

        Returns:
            Outputs.
        """
        policies_xml = client.list_policies_request()
        policies_json = xml2json(policies_xml)
        policies = json.loads(policies_json)
        policies_arr = policies.get("policies").get("policy")
        policies_readable, policies_outputs = parse_data_arr(policies_arr)
        headers = ["ID", "Name", "Criticality", "Created On", "Created By", "Description"]
        human_readable = tableToMarkdown(name="Policies:", t=policies_readable, headers=headers, removeNull=True)
        entry_context = {"Securonix.Policies(val.ID === obj.ID)": policies_outputs}

        return human_readable, entry_context, policies


    def list_resource_groups(client: Client, *_) -> tuple[str, dict, dict]:
        """List all resource groups.

        Args:
            client: Client object with request.
            *_:

        Returns:
            Outputs.
        """
        resource_groups_xml = client.list_resource_groups_request()

        resource_groups_json = xml2json(resource_groups_xml)
        resource_groups = json.loads(resource_groups_json)
        resource_groups_arr = resource_groups.get("resourceGroups").get("resourceGroup")

        resource_groups_readable, resource_groups_outputs = parse_data_arr(resource_groups_arr)
        headers = ["Name", "Type"]
        human_readable = tableToMarkdown(name="Resource groups:", t=resource_groups_readable, headers=headers, removeNull=True)
        entry_context = {"Securonix.ResourceGroups(val.Name === obj.Name)": resource_groups_outputs}

        return human_readable, entry_context, resource_groups


    def list_users(client: Client, *_) -> tuple[str, dict, dict]:
        """List all users.

        Args:
            client: Client object with request.
            *_:

        Returns:
            Outputs.
        """
        users_xml = client.list_users_request()

        users_json = xml2json(users_xml)
        users = json.loads(users_json)
        users_arr = users.get("users").get("user")

        users_readable, users_outputs = parse_data_arr(users_arr)
        headers = ["Employee Id", "First Name", "Last Name", "Criticality", "Title", "Email"]
        human_readable = tableToMarkdown(name="Resource groups:", t=users_readable, headers=headers, removeNull=True)
        entry_context = {"Securonix.Users(val.EmployeeID === obj.EmployeeID)": users_outputs}

        return human_readable, entry_context, users


    def list_activity_data(client: Client, args) -> tuple[str, dict, dict]:
        """List activity data.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        from_ = args.get("from", "").strip()
        to_ = args.get("to", "").strip()
        query = escape_spotter_query(args.get("query", "").strip())
        max_records = arg_to_number(args.get("max", "1000"), arg_name="max")

        if max_records is not None and (max_records < 1 or max_records > 10000):
            raise ValueError(MESSAGE["INVALID_MAX_VALUE"])

        activity_data = client.list_activity_data_request(from_, to_, query, max_records)  # type: ignore

        if activity_data.get("error"):
            raise Exception(
                f"Failed to get activity data in the given time frame.\nError from Securonix is: {activity_data.get('errorMessage')}"
            )

        activity_events = activity_data.get("events")
        activity_readables, activity_outputs = parse_data_arr(activity_events)
        for index, activity in enumerate(activity_readables):
            if activity.get("Eventid"):
                activity["EventID"] = activity.get("Eventid")
                del activity["Eventid"]
            if index < len(activity_outputs) and activity_outputs[index].get("Eventid"):
                activity_outputs[index]["EventID"] = activity_outputs[index].get("Eventid")
                del activity_outputs[index]["Eventid"]
            if "Timeline" in activity:
                activity["Timeline"] = timestamp_to_datestring(activity.get("Timeline", 0), is_utc=True)
        headers = ["EventID", "Eventtime", "Message", "Accountname", "Timeline", "Devicehostname", "Accountresourcekey"]
        human_readable = tableToMarkdown(
            name="Activity data:",
            t=[
                {key: string_escape_MD(value) for key, value in activity_readable.items()} for activity_readable in activity_readables
            ],
            headers=headers,
            removeNull=True,
        )

        pagination_data = {
            "totalDocuments": activity_data.get("totalDocuments"),
            "message": activity_data.get("message"),
            "queryId": activity_data.get("queryId"),
            "command_name": "securonix-list-activity-data",
        }

        entry_context = {"Securonix.Activity(val.command_name === obj.command_name)": remove_empty_elements(pagination_data)}

        activity_outputs = remove_empty_elements(activity_outputs)
        if activity_outputs:
            entry_context["Securonix.ActivityData(val.EventID === obj.EventID)"] = activity_outputs

        return human_readable, entry_context, activity_data


    def list_violation_data(client: Client, args) -> list[CommandResults]:
        """List violation data.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        from_ = args.get("from", "").strip()
        to_ = args.get("to", "").strip()
        query = escape_spotter_query(args.get("query", "").strip())
        query_id = args.get("query_id", "").strip()
        max_violations = arg_to_number(args.get("max", "1000"))

        if max_violations is not None and max_violations <= 0:
            raise ValueError(MESSAGE["INVALID_MAX_VALUE"])

        violation_data = client.list_violation_data_request(from_, to_, query, query_id, max_violations)

        if violation_data.get("error"):
            raise Exception(
                f"Failed to get violation data in the given time frame.\n"
                f"Error from Securonix is: {violation_data.get('errorMessage')}"
            )
        violation_events = violation_data.get("events")
        if len(violation_events) > 0:  # type: ignore[arg-type]
            violation_readables, violation_outputs = parse_data_arr(violation_events)
            headers = ["EventID", "Eventtime", "Message", "Policyname", "Accountname"]
            human_readable = tableToMarkdown(
                name="Activity data:",
                t=[
                    {key: string_escape_MD(value) for key, value in violation_readable.items()}
                    for violation_readable in violation_readables
                ],
                headers=headers,
                removeNull=True,
            )

            data = {
                "totalDocuments": violation_data.get("totalDocuments"),
                "message": violation_data.get("message"),
                "queryId": violation_data.get("queryId"),
            }

            return [
                CommandResults(
                    outputs_prefix="Securonix.ViolationData",
                    readable_output=human_readable,
                    outputs=remove_empty_elements(violation_outputs),
                    raw_response=violation_data,
                    outputs_key_field=[
                        "Policyname",
                        "Violator",
                        "Resourcegroupid",
                        "Tenantname",
                        "Resourcename",
                        "EmployeeID",
                        "Accountname",
                        "Ipaddress",
                    ],
                ),
                CommandResults(
                    outputs_prefix="Securonix.Violation",
                    outputs=remove_empty_elements(data),
                    readable_output=f"#### Next page query id: {data.get('queryId')}",
                ),
            ]
        else:
            return [CommandResults(readable_output="There are no violation events.", outputs={}, raw_response=violation_data)]


    def run_polling_command(client, args: dict, command_name: str, search_function: Callable):
        """
        For Scheduling command.

        Args:
            client: Client object with request.
            args: Command arguments.
            command_name: Name of the command.
            search_function: Callable object of command.

        Returns:
            Outputs.
        """
        command_results = []
        result = search_function(client, args)
        command_results.append(result)
        outputs = result[0].raw_response.get("events")
        delay_type = client.get_securonix_retry_delay_type()
        retry_count: int = client.get_securonix_retry_count()
        retry_delay: int = client.get_securonix_retry_delay()

        if len(outputs) == 0 and retry_count > 0:
            if delay_type == "Exponential":
                retry_delay = client.get_securonix_retry_delay() * 2
            retry_timeout: int = retry_delay * retry_count + retry_count * 1
            policy_type = args.get("policy_type", "").strip().upper()
            if policy_type in POLICY_TYPES_TO_RETRY:
                args["to"] = datetime.now().astimezone(timezone.utc).strftime(r"%m/%d/%Y %H:%M:%S")
            polling_args = {"polling": True, **args}
            scheduled_command = ScheduledCommand(
                command=command_name, next_run_in_seconds=retry_delay, args=polling_args, timeout_in_seconds=retry_timeout
            )
            command_results.append(CommandResults(scheduled_command=scheduled_command))
            return command_results
        return result


    def list_incidents(client: Client, args: dict) -> tuple[str, dict, dict]:
        """List incidents.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        from_, _ = parse_date_range(args.get("from"), utc=True)
        from_epoch = date_to_timestamp(from_, date_format=timestamp_format)
        to_ = args.get("to") if "to_" in args else datetime.now()
        to_epoch = date_to_timestamp(to_, date_format=timestamp_format)
        incident_types = str(args.get("incident_types")) if "incident_types" in args else "opened"
        max_incidents = str(args.get("max", "50"))
        incidents = client.list_incidents_request(from_epoch, to_epoch, incident_types, max_incidents)

        total_incidents = incidents.get("totalIncidents")
        if not total_incidents or float(total_incidents) <= 0.0:
            return "No incidents where found in this time frame.", {}, incidents

        incidents_items: list = incidents.get("incidentItems", [])
        incidents_readables, incidents_outputs = parse_data_arr(incidents_items)
        headers = ["IncidentID", "Incident Status", "Incident Type", "Priority", "Reason"]
        human_readable = tableToMarkdown(
            name="Incidents:",
            t=[
                {key: string_escape_MD(value) for key, value in incidents_readable.items()}
                for incidents_readable in incidents_readables
            ],
            headers=headers,
            removeNull=True,
        )
        entry_context = {"Securonix.Incidents(val.IncidentID === obj.IncidentID)": incidents_outputs}
        return human_readable, entry_context, incidents


    def get_incident(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Get incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))
        incident = client.get_incident_request(incident_id)

        incident_items = incident.get("incidentItems")
        if not incident_items:
            raise Exception("Incident ID is not in Securonix.")
        incident_readables, incident_outputs = parse_data_arr(incident_items)
        human_readable = tableToMarkdown(
            name="Incident:",
            t=[
                {key: string_escape_MD(value) for key, value in incident_readable.items()} for incident_readable in incident_readables
            ],
            removeNull=True,
        )
        entry_context = {"Securonix.Incidents(val.IncidentID === obj.IncidentID)": incident_outputs}
        return human_readable, entry_context, incident


    def get_incident_status(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Get incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))
        incident = client.get_incident_status_request(incident_id)
        incident_status = incident.get("status")
        incident_outputs = {"IncidentID": incident_id, "IncidentStatus": incident_status}
        entry_context = {"Securonix.Incidents(val.IncidentID === obj.IncidentID)": incident_outputs}
        return f"Incident {incident_id} status is {incident_status}.", entry_context, incident


    def get_incident_workflow(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Get incident workflow.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))

        incident = client.get_incident_workflow_request(incident_id)
        incident_workflow = incident.get("workflow")
        incident_outputs = {"IncidentID": incident_id, "WorkflowName": incident_workflow}
        entry_context = {"Securonix.Incidents(val.IncidentId === obj.IncidentId)": incident_outputs}
        return f"Incident {incident_id} workflow is {incident_workflow}.", entry_context, incident


    def get_incident_available_actions(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Get incident available actions.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))

        incident_actions = client.get_incident_available_actions_request(incident_id)
        if not incident_actions:
            return f"Incident {incident_id} does not have any available actions.", {}, incident_actions
        actions = []
        for action_details in incident_actions:
            actions.append(action_details.get("actionName"))

        incident_outputs = {"IncidentID": incident_id, "AvailableActions": actions}
        entry_context = {"Securonix.Incidents(val.IncidentID === obj.IncidentID)": incident_outputs}
        return f"Incident {incident_id} available actions: {actions}.", entry_context, incident_actions


    def get_incident_attachments(client: Client, args: dict, incident_id: str = None):
        """Get incident attachments.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
            incident_id: Incident ID

        Returns:
            Outputs.
        """
        incident_id_ = args.get("incident_id", "").strip()
        attachment_type = ",".join(argToList(args.get("attachment_type")))
        attachment_from = args.get("from")
        attachment_to = args.get("to")
        if attachment_from:
            attachment_from = attachment_from.strip()
            attachment_from = date_to_timestamp(arg_to_datetime(attachment_from, arg_name="attachment_from"))
        if attachment_to:
            attachment_to = attachment_to.strip()
            attachment_to = date_to_timestamp(arg_to_datetime(attachment_to, arg_name="attachment_to"))

        if incident_id:
            attachments_res = client.get_incident_attachments_request(incident_id)
        else:
            attachments_res = client.get_incident_attachments_request(
                incident_id_,
                attachment_type,
                attachment_from,  # type: ignore
                attachment_to,
            )  # type: ignore
        try:
            # So if there is no attachments then in response status code will be 200 and in content there is json with
            # error field
            if "Content-Disposition" not in attachments_res.headers:
                return CommandResults(readable_output=f"#### No Attachments found for Incident ID: {incident_id_}")
        except requests.exceptions.JSONDecodeError:  # type: ignore
            # Here if API have attachments then it will return byte data so then res.json() raise decode error. Means we
            # received attachments that's in below code there is debug log
            demisto.debug("Retrieved attachment for incident.")

        content_disposition = attachments_res.headers.get("Content-Disposition")
        filename = content_disposition.split(";")[1].replace("filename=", "")
        file_list = []
        if filename.startswith(incident_id or incident_id_):
            zip_obj = ZipFile(io.BytesIO(attachments_res.content))
            zip_filenames = zip_obj.namelist()
            zip_obj.extractall(path=os.path.abspath(os.getcwd()))
            zip_obj.close()
            file_list.append(
                CommandResults(
                    outputs_prefix="Securonix.Incidents.Attachments",
                    outputs=[{"IncidentID": incident_id_, "Files": zip_filenames}],
                    readable_output=f"### Incident ID: {incident_id_}",
                )
            )
            for name in zip_filenames:
                with open(name, "br") as file:
                    file_list.append(fileResult(filename=name, data=file.read()))
            return file_list
        else:
            file_list.extend(
                [
                    CommandResults(
                        outputs_prefix="Securonix.Incidents.Attachments",
                        outputs=[{"IncidentID": incident_id_, "Files": filename}],
                        readable_output=f"### Incident ID: {incident_id_}",
                    ),
                    fileResult(filename=filename, data=attachments_res.content),
                ]
            )
            return file_list


    def perform_action_on_incident(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Perform action on an incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))
        action = str(args.get("action"))
        action_parameters = str(args.get("action_parameters", ""))
        incident_result = client.perform_action_on_incident_request(incident_id, action, action_parameters)
        if incident_result != "submitted":
            raise Exception(f"Failed to perform the action {action} on incident {incident_id}.")
        return f"Action {action} was performed on incident {incident_id}.", {}, incident_result


    def add_comment_to_incident(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Add comment to an incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = str(args.get("incident_id"))
        comment = str(args.get("comment"))
        incident = client.add_comment_to_incident_request(incident_id, comment)
        if not incident:
            raise Exception(f"Failed to add comment to the incident {incident_id}.")
        return f"Comment was added to the incident {incident_id} successfully.", {}, incident


    def create_incident(client: Client, args: dict) -> tuple[str, dict, dict]:
        """Create an incident.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        violation_name = str(args.get("violation_name"))
        resource_group = str(args.get("resource_group"))
        resource_name = str(args.get("resource_name"))
        entity_type = str(args.get("entity_type"))
        entity_name = str(args.get("entity_name"))
        action_name = str(args.get("action_name"))
        workflow = str(args.get("workflow")) if "workflow" in args else None
        comment = str(args.get("comment")) if "comment" in args else None
        criticality = str(args.get("criticality")) if "criticality" in args else None

        if "create incident" in action_name and not workflow:
            raise Exception(f"Creating an incident with the action: {action_name}, Supply a workflow.")
        response = client.create_incident_request(
            violation_name, resource_group, resource_name, entity_type, entity_name, action_name, workflow, comment, criticality
        )
        result = response.get("result")
        if not result:
            raise Exception(f"Failed to create the incident.\nResponse from Securonix is: {response!s}")

        message = response.get("messages")
        if message:
            if isinstance(message, list) and "Invalid" in message[0]:
                message = message[0]
                raise Exception(f"Failed to create the incident with message: \n{message}")
            if "Invalid" in message:
                raise Exception(f"Failed to create the incident with message: \n{message}")

        incident_data = result.get("data")
        incident_items = incident_data.get("incidentItems")
        incident_readable, incident_outputs = parse_data_arr(incident_items)
        headers = ["Entity", "Incident Status", "Incident Type", "IncidentID", "Priority", "Reason", "Url"]
        human_readable = tableToMarkdown(
            name="Incident was created successfully", t=incident_readable, headers=headers, removeNull=True
        )
        entry_context = {"Securonix.Incidents(val.IncidentID === obj.IncidentID)": incident_outputs}
        return human_readable, entry_context, response


    def list_watchlists(client: Client, *_) -> tuple[str, dict, dict]:
        """List all watchlists.

        Args:
            client: Client object with request.

        Returns:
            Outputs.
        """
        watchlists = client.list_watchlist_request()
        if not watchlists:
            raise Exception("Failed to list watchlists.")

        human_readable = f"Watchlists: {', '.join(watchlists)}."
        entry_context = {"Securonix.WatchlistsNames": watchlists}
        return human_readable, entry_context, watchlists


    def get_watchlist(client: Client, args) -> tuple[str, dict, dict]:
        """Get watchlist data.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
        Returns:
            Outputs.
        """
        watchlist_name = args.get("watchlist_name", "").strip()
        watchlist = client.get_watchlist_request(watchlist_name)

        watchlist_events = watchlist.get("events")
        if not watchlist_events:
            raise Exception(
                "Watchlist does not contain items.\nMake sure the watchlist is not empty and that the watchlist name is correct."
            )
        fields_to_drop = ["decayflag", "tenantid", "tenantname", "watchlistname", "type"]
        watchlist_readable, watchlist_events_outputs = parse_data_arr(watchlist_events, fields_to_drop=fields_to_drop)
        watchlist_outputs = {
            "Watchlistname": watchlist_name,
            "Type": watchlist_events[0].get("type"),
            "TenantID": watchlist_events[0].get("tenantid"),
            "TenantName": watchlist_events[0].get("tenantname"),
            "Events": watchlist_events_outputs,
        }
        headers = ["Entityname", "Fullname", "Workemail", "Expired"]
        human_readable = tableToMarkdown(
            name=f"Watchlist {watchlist_name} of type {watchlist_outputs.get('Type')}: ",
            t=watchlist_readable,
            headers=headers,
            removeNull=True,
        )
        entry_context = {"Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)": watchlist_outputs}
        return human_readable, entry_context, watchlist


    def create_watchlist(client: Client, args) -> tuple[str, dict, dict]:
        """Create a watchlist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
        Returns:
            Outputs.
        """
        watchlist_name = args.get("watchlist_name", "").strip()
        tenant_name = args.get("tenant_name", "").strip()

        response = client.create_watchlist_request(watchlist_name, tenant_name)

        if "successfully" not in response:
            raise Exception(f"Failed to list watchlists.\nResponse from Securonix is: {response!s}")
        human_readable = f"Watchlist {watchlist_name} was created successfully."
        watchlist = {"Watchlistname": watchlist_name, "TenantName": tenant_name}
        remove_nulls_from_dictionary(watchlist)
        entry_context = {
            "Securonix.Watchlists(val.Watchlistname === obj.Watchlistname && val.TenantName === obj.TenantName)": watchlist
        }
        return human_readable, entry_context, response


    def check_entity_in_watchlist(client: Client, args) -> tuple[str, dict, dict]:
        """Check if entity is in a watchlist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
        Returns:
            Outputs.
        """
        entity_name = args.get("entity_name")
        watchlist_name = args.get("watchlist_name")
        watchlist = client.check_entity_in_watchlist_request(entity_name, watchlist_name)

        result = watchlist.get("result")
        if result == "NO" or (isinstance(result, list) and result[0] == "NO"):
            human_readable = f"Entity unique identifier {entity_name} provided is not on the watchlist: {watchlist_name}."
            output = {"Entityname": entity_name}
        else:  # YES
            human_readable = f"The Entity unique identifier {entity_name} provided is on the watchlist: {watchlist_name}."
            output = {"Entityname": entity_name, "Watchlistname": watchlist_name}
        entry_context = {"Securonix.EntityInWatchlist(val.Entityname === obj.Entityname)": output}
        return human_readable, entry_context, watchlist


    def add_entity_to_watchlist(client: Client, args) -> tuple[str, dict, dict]:
        """Adds an entity to a watchlist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
        Returns:
            Outputs.
        """
        watchlist_name = args.get("watchlist_name")
        entity_type = args.get("entity_type")
        entity_name = args.get("entity_name")
        expiry_days = args.get("expiry_days") if "expiry_days" in args else "30"

        response = client.add_entity_to_watchlist_request(watchlist_name, entity_type, entity_name, expiry_days)

        if "successfull" not in response:
            raise Exception(
                f"Failed to add entity {entity_name} to the watchlist {watchlist_name}.\nError from Securonix is: {response}."
            )
        human_readable = f"Added successfully the entity {entity_name} to the watchlist {watchlist_name}."
        return human_readable, {}, response


    def list_threats(client: Client, args: dict[str, Any]) -> tuple[str, dict, dict]:
        """List threats violated within a specified time range and get details about the threat models and policies violated.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        date_from = date_to_timestamp(arg_to_datetime(args.get("date_from"), arg_name="date_from"))
        date_to = date_to_timestamp(
            arg_to_datetime(args.get("date_to", datetime.now().strftime("'%Y-%m-%dT%H:%M:%S'")), arg_name="date_to")
        )
        page_size = arg_to_number(args.get("page_size", 10), arg_name="page_size")
        tenant_name = args.get("tenant_name")
        offset = arg_to_number(args.get("offset", 0), arg_name="offset")

        threat_response = client.list_threats_request(date_from, date_to, tenant_name, offset, page_size)  # type: ignore
        threat_response = remove_empty_elements(threat_response)

        threat_readable, threats_outputs = parse_data_arr(threat_response)

        headers = [
            "ThreatName",
            "EntityID",
            "Violator",
            "Category",
            "Resourcegroupname",
            "Resourcename",
            "Resourcetype",
            "GenerationTime",
            "Policies",
            "TenantID",
            "Tenantname",
        ]
        human_readable = tableToMarkdown(name="Threats:", t=threat_readable, headers=headers, removeNull=True)
        entry_context = {
            "Securonix.Threat(val.EntityID === obj.EntityID && val.Resourcename === obj.Resourcename && val.Resourcetype "
            "=== obj.Resourcetype && val.Resourcegroupname === obj.Resourcegroupname && val.Policies.toString() === "
            "obj.Policies.toString())": threats_outputs
        }
        return human_readable, entry_context, threat_response


    def get_incident_activity_history(client: Client, args: dict[str, Any]) -> tuple[str, dict, list]:
        """Get the incident activity history for the specified incident ID.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        incident_id = args.get("incident_id", "").strip()

        # Raises error when user has provided '  ' in input.
        if not incident_id:
            raise ValueError("Incident ID is a required parameter.")

        # Retrieve activity history for the specified incident ID.
        activity_history = client.get_incident_activity_history_request(incident_id)

        # Prepare entry context for the command.
        # As the response is in such a format, we can not determine a primary key for the context data.
        entry_context = {"Securonix.IncidentHistory": activity_history}

        # Prepare human-readable output for the command.
        activity_history_readable = [
            {
                "Action Taken": h.get("actiontaken"),
                "Username": h.get("username"),
                "Event Time": h.get("eventTime"),
                "Status": h.get("status"),
                "Last Status": h.get("lastStatus"),
                "Comment": "\n".join([c.get("Comments", "") for c in h.get("comment", [])]),
                "Playbook ID": h.get("playBookOutput", {}).get("playBookId"),
                "Playbook Name": h.get("playBookOutput", {}).get("playBookName"),
                "Playbook Executor": h.get("playBookOutput", {}).get("executor"),
                "Attachment Name": h.get("attachment"),
            }
            for h in activity_history
        ]

        # Reversing the human-readable list, as we want to show the latest activity first, rather than the old.
        activity_history_readable.reverse()

        headers = [
            "Action Taken",
            "Username",
            "Event Time",
            "Status",
            "Last Status",
            "Comment",
            "Playbook ID",
            "Playbook Name",
            "Playbook Executor",
            "Attachment Name",
        ]
        human_readable = tableToMarkdown(
            f"Incident activity history for ID: {incident_id}", t=activity_history_readable, headers=headers, removeNull=True
        )

        return human_readable, entry_context, activity_history


    def list_whitelists(client: Client, args: dict[str, Any]) -> tuple[str, dict, list]:
        """List all whitelist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        tenant_name = args.get("tenant_name", "").strip()

        whitelists = client.list_whitelists_request(tenant_name)

        whitelists_entries = []

        for whitelist in whitelists:
            whitelist_details = whitelist.split("|", 3)
            if len(whitelist_details) < 3:
                empty_details = 3 - len(whitelist_details)
                whitelist_details += "null" * empty_details
            whitelists_entries.append(
                {
                    "WhitelistName": whitelist_details[0].strip().replace("null", ""),
                    "WhitelistType": whitelist_details[1].strip().replace("null", ""),
                    "TenantName": whitelist_details[2].strip().replace("null", ""),
                }
            )

        whitelists_entries = remove_empty_elements(whitelists_entries)

        headers = ["WhitelistName", "WhitelistType", "TenantName"]
        human_readable = tableToMarkdown(name="Whitelists:", t=whitelists_entries, headers=headers, removeNull=True)
        entry_context = {
            "Securonix.Whitelist(val.WhitelistName === obj.WhitelistName && val.TenantName === obj.TenantName)": whitelists_entries
        }

        return human_readable, entry_context, whitelists


    def get_whitelist_entry(client: Client, args: dict[str, Any]) -> tuple[str, dict, dict]:
        """Get information for the specified whitelist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        tenant_name = args.get("tenant_name", "").strip()
        whitelist_name = args.get("whitelist_name", "").strip()

        whitelist = client.get_whitelist_entry_request(tenant_name, whitelist_name)

        if not whitelist:
            raise Exception("Whitelist does not contain items.\nMake sure the whitelist_name is not empty and it is correct.")

        whitelist_entries = []

        for key, val in whitelist.items():
            whitelist_entries.append({"Entity/Attribute": key, "ExpiryDate": val})
        watchlist_outputs = {"WhitelistName": whitelist_name, "TenantName": tenant_name, "Entries": whitelist_entries}
        remove_nulls_from_dictionary(watchlist_outputs)

        headers = ["Entity/Attribute", "ExpiryDate"]
        human_readable = tableToMarkdown(
            name=f"Whitelist: {whitelist_name}", t=remove_empty_elements(whitelist_entries), headers=headers, removeNull=True
        )
        entry_context = {
            "Securonix.Whitelist(val.WhitelistName === obj.WhitelistName && val.TenantName === obj.TenantName)": watchlist_outputs
        }

        return human_readable, entry_context, whitelist


    def add_whitelist_entry(client: Client, args) -> tuple[str, dict, dict]:
        """Adds an entry to a whitelist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()
        Returns:
            Outputs.
        """
        tenant_name = args.get("tenant_name", "").strip()
        whitelist_name = args.get("whitelist_name", "").strip()
        whitelist_type = args.get("whitelist_type", "").strip()
        entity_type = args.get("entity_type", "").strip()
        entity_id = args.get("entity_id", "").strip()
        expiry_date = args.get("expiry_date", "").strip()
        resource_name = args.get("resource_name", "").strip()
        resource_group_id = args.get("resource_group_id", "").strip()
        attribute_name = args.get("attribute_name", "").strip()
        attribute_value = args.get("attribute_value", "").strip()
        violation_type = args.get("violation_type", "").strip()
        violation_name = args.get("violation_name", "").strip()

        if whitelist_type not in ["Global", "Attribute"]:
            raise Exception("Provide valid whitelist_type")

        if whitelist_type == "Global" and entity_type not in ["Users", "Activityaccount", "Resources", "Activityip"]:
            raise Exception("Provide valid entity_type")

        if whitelist_type == "Attribute":
            if attribute_name not in ["source ip", "resourcetype", "transactionstring"]:
                raise Exception("Provide valid attribute_name")

            if violation_type not in ["Policy", "ThreatModel", "Functionality"]:
                raise Exception("Provide valid violation_type")

        try:
            if expiry_date:
                datetime.strptime(expiry_date, "%m/%d/%Y")
        except ValueError:
            raise Exception("exipry_date is not in MM/DD/YYYY format")

        response = client.add_whitelist_entry_request(
            tenant_name,
            whitelist_name,
            whitelist_type,
            entity_type,
            entity_id,
            expiry_date,
            resource_name,
            resource_group_id,
            attribute_name,
            attribute_value,
            violation_type,
            violation_name,
        )
        if response.get("status_code") == 400:
            raise Exception(f"Failed to add entity to the whitelist.\nError from Securonix is: {response}.")
        human_readable = "Entity added to global whitelist Successfully."

        return human_readable, {}, response


    def create_whitelist(client: Client, args) -> tuple[str, dict, dict]:
        """Create a whitelist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        tenant_name = args.get("tenant_name", "").strip()
        whitelist_name = args.get("whitelist_name", "").strip()
        entity_type = args.get("entity_type", "").strip()

        if entity_type not in VALID_ENTITY_TYPE:
            raise Exception(f"{entity_type} is invalid entity_type. Valid entity types are {VALID_ENTITY_TYPE}")

        response = client.create_whitelist_request(tenant_name, whitelist_name, entity_type)

        if "successfully" not in str(response.get("messages")).lower():
            raise Exception(f"Failed to create whitelist.\nResponse from Securonix is: {response!s}")

        human_readable = f"Whitelist {whitelist_name} was created successfully."

        return human_readable, {}, response


    def delete_lookup_table_config_and_data(client: Client, args: dict[str, Any]) -> tuple:
        """Delete a lookup table and its configuration data from Securonix.

        Args:
            client (Client): Client object with request.
            args: (Dict[str, Any]): Usually demisto.args().

        Returns:
            Outputs.
        """
        name = args.get("name", "").strip()

        if not name:
            raise ValueError("Lookup table name is a required argument.")

        response = client.delete_lookup_table_config_and_data_request(name=name)

        if "successfully" not in response.lower():
            raise Exception(f"Failed to delete lookup table and its data.\nResponse from Securonix is: {response!s}")

        human_readable = f"The table {name} has been deleted successfully on Securonix."

        entry_context = {
            "Securonix.LookupTable(val.lookupTableName === obj.lookupTableName)": {"lookupTableName": name, "isDeleted": True}
        }
        return human_readable, entry_context, response


    def delete_whitelist_entry(client: Client, args) -> tuple[str, dict, dict]:
        """Delete an entry from the whitelist.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        tenant_name = args.get("tenant_name", "").strip()
        whitelist_name = args.get("whitelist_name", "").strip()
        whitelist_type = args.get("whitelist_type", "").strip()
        entity_id = args.get("entity_id", "").strip()
        attribute_name = args.get("attribute_name", "").strip()
        attribute_value = args.get("attribute_value", "").strip()

        validate_delete_whitelist_parameters(whitelist_type, entity_id, attribute_name, attribute_value, tenant_name)

        response = client.delete_whitelist_entry_request(
            tenant_name, whitelist_name, whitelist_type, entity_id, attribute_name, attribute_value
        )
        result = response.get("result", [])

        if "successfully" not in str(result).lower():
            raise Exception(f"Failed to remove entry from whitelist.\nResponse from Securonix is: {result!s}")

        human_readable = "".join(result).replace(" ..! ", ".")

        return human_readable, {}, response


    def list_lookup_tables(client: Client, args: dict[str, Any]) -> tuple[str, dict, list]:
        """Retrieves a list of lookup tables available within the Securonix platform.

        Args:
            client (Client): Client object with request.
            args: (Dict[str, Any]): Usually demisto.args().

        Returns:
            Outputs.
        """
        max_records = arg_to_number(args.get("max", "50").strip() or "50")
        offset = arg_to_number(args.get("offset", "0").strip() or "0")

        lookup_tables = client.get_lookup_tables_request(max_records=max_records, offset=offset)

        lookup_table_readable = [
            {
                "Tenant Name": table.get("tenantName", ""),
                "Lookup Table Name": table.get("lookupTableName", ""),
                "Total Records": table.get("totalRecords", ""),
                "Scope": table.get("scope", ""),
                "Type of Lookup Table": table.get("type", ""),
            }
            for table in lookup_tables
        ]

        headers = ["Tenant Name", "Lookup Table Name", "Total Records", "Scope", "Type of Lookup Table"]
        human_readable = tableToMarkdown("Lookup Tables:", t=lookup_table_readable, headers=headers, removeNull=True)

        entry_context = {"Securonix.LookupTable(val.lookupTableName === obj.lookupTableName)": remove_empty_elements(lookup_tables)}

        return human_readable, entry_context, lookup_tables


    def validate_expiry_time_of_lookup_table_entries(table_entries: Union[dict, list[dict]]) -> None:
        """Check whether the expiration time of the lookup table entries is valid.

        Args:
            table_entries (Union[Dict, List[Dict]]): Lookup table entries to add to the lookup table.
        """

        def is_expiration_time_in_valid_format(expiration_time: str) -> None:
            try:
                datetime.strptime(expiration_time, "%m/%d/%Y")
            except ValueError as exception:
                raise ValueError("The value of expiryDate field is not in MM/DD/YYYY format.") from exception

        if isinstance(table_entries, dict):
            expiration_time = table_entries.get("expiryDate")

            if expiration_time:
                is_expiration_time_in_valid_format(expiration_time)

        if isinstance(table_entries, list):
            for entry in table_entries:
                expiration_time = entry.get("expiryDate")

                if expiration_time:
                    is_expiration_time_in_valid_format(expiration_time)


    def add_entry_to_lookup_table(client: Client, args: dict[str, Any]) -> tuple:
        """Add entries to the lookup table.

        Args:
            client (Client): Client object with request.
            args: (Dict[str, Any]): Usually demisto.args().

        Returns:
            Outputs.
        """
        table_name = args.get("name", "").strip()
        tanant_name = args.get("tenant_name", "").strip()
        json_data = args.get("json_data", "").strip()
        entry_id = args.get("file_entry_id", "").strip()

        # Validate the command arguments.
        if not table_name:
            raise ValueError("Lookup table name is a required parameter.")

        if not json_data and not entry_id:
            raise ValueError("Either JSON data or file entry ID is required to add data to lookup table.")

        # File will take precedence over JSON data.
        if entry_id:
            file_obj = demisto.getFilePath(entry_id)
            file_path = file_obj.get("path")

            try:
                with open(file_path) as file:
                    json_entries = json.loads(file.read())
            except json.JSONDecodeError as exception:
                raise Exception(f"Could not able to parse the provided JSON data. Error: {exception!s}") from exception
        else:
            try:
                json_entries = json.loads(json_data)
            except json.JSONDecodeError as exception:
                raise Exception(f"Could not able to parse the provided JSON data. Error: {exception!s}") from exception

        validate_expiry_time_of_lookup_table_entries(table_entries=json_entries)

        if isinstance(json_entries, dict):
            json_entries = [json_entries]

        response = client.add_entry_to_lookup_table_request(name=table_name, entries=json_entries, tenant_name=tanant_name)

        if "successfully" not in response.lower():
            raise Exception(f"Failed adding entries to the lookup table. Error from Securonix: {response!s}")

        return response, {}, response


    def prepare_entry_contex_lookup_table_entries_list(entries: list[dict]) -> list[dict]:
        """Prepare entry context for list-lookup-table-entries command.

        Args:
            entries (List[Dict]): Response received from API.

        Returns:
            List[Dict]: Entry context list.
        """
        new_entries = []

        for entry in entries:
            new_entry: dict[str, Any] = {"entry": []}

            for key, value in entry.items():
                if key.startswith("value_"):
                    new_entry["entry"].append(
                        {
                            "key": key[6:],  # Remove "value_" from the key.
                            "value": value,
                        }
                    )
                else:
                    new_entry[key] = value

            new_entries.append(new_entry)

        return new_entries


    def prepare_human_readable_for_lookup_table_entries_list(entries: list[dict]) -> str:
        """Prepare human-readable string for lookup-table-entries-list command.

        Args:
            entries (List[Dict]): List of entries.

        Returns:
            str: Markdown string.
        """
        table = []

        for entry in entries:
            new_entry = {
                "Key": entry.get("key"),
                "Timestamp": entry.get("timestamp"),
                "Lookup Unique Key": entry.get("lookupuniquekey"),
                "Tenant Name": entry.get("tenantname"),
            }
            for e in entry.get("entry", []):
                new_entry[e["key"]] = e["value"]
            table.append(new_entry)

        return tableToMarkdown(name="Entries:", t=table, removeNull=True)


    def list_lookup_table_entries(client: Client, args: dict[str, Any]) -> tuple:
        """List the entries of the provided lookup table.

        Args:
            client (Client): Client object with request.
            args (Dict[str, Any]): Usually demisto.args().

        Returns:
            Outputs.
        """
        name = args.get("name", "").strip()
        query = args.get("query", "").strip()
        attribute = args.get("attribute", "key").strip() or "key"
        max_records = arg_to_number(args.get("max", "15").strip() or "15")
        offset = arg_to_number(args.get("offset", "0").strip() or "0")
        page_num = arg_to_number(args.get("page_num", "1").strip() or "1")
        sort = args.get("sort", "").strip()
        order = args.get("order", "asc").strip().lower() or "asc"

        # Validate required parameters.
        if not name:
            raise ValueError("Lookup table name is a required argument.")

        # Validate order argument.
        if order and order not in ["asc", "desc"]:
            raise ValueError('Order argument must be "asc" or "desc".')

        response = client.list_lookup_table_entries_request(
            name=name,
            query=query,
            attribute=attribute,
            max_records=max_records,
            offset=offset,
            page_num=page_num,
            sort=sort,
            order=order,
        )

        entry_context_list: list[dict] = prepare_entry_contex_lookup_table_entries_list(response)
        human_readable = prepare_human_readable_for_lookup_table_entries_list(entry_context_list)

        entry_context = {
            "Securonix.LookupTableEntries(val.lookupuniquekey === obj.lookupuniquekey)": remove_empty_elements(entry_context_list)
        }

        return human_readable, entry_context, response


    def create_lookup_table(client: Client, args) -> tuple[str, dict, dict]:
        """Create a lookup table.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        name = args.get("name", "").strip()
        scope = args.get("scope")
        tenant_name = args.get("tenant_name", "").strip()
        field_names = argToList(args.get("field_names", "").strip())
        encrypt = argToList(args.get("encrypt", "").strip())
        key = argToList(args.get("key", "").strip())

        response = client.create_lookup_table_request(tenant_name, name, scope, field_names, encrypt, key)
        if "successfully" not in response.lower():  # type: ignore[attr-defined]
            raise Exception(f"Failed to create lookup table.\nResponse from Securonix is: {response}")
        human_readable = f"Lookup Table {name} created successfully."

        return human_readable, {}, response


    def delete_lookup_table_entries(client: Client, args: dict[str, Any]):
        """Delete entries from the lookup table.

        Args:
            client: Client object with request.
            args: Usually demisto.args()

        Returns:
            Outputs.
        """
        name = args.get("name", "").strip()
        lookup_unique_keys = argToList(args.get("lookup_unique_keys", "").strip())

        if not name:
            raise ValueError("Lookup table name is a required parameter.")

        if not lookup_unique_keys:
            raise ValueError("At least one lookup table key is required to execute the command.")

        response = client.delete_lookup_table_entries(name=name, lookup_unique_keys=lookup_unique_keys)
        human_readable = f"Successfully deleted following entries from {name}: {', '.join(lookup_unique_keys)}."

        return human_readable, {}, response


    def fetch_securonix_incident(
        client: Client,
        fetch_time: str | None,
        incident_status: str,
        default_severity: str,
        max_fetch: str,
        last_run: dict,
        close_incident: bool,
    ) -> list:
        """Uses to fetch incidents into Demisto
        Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

        Args:
            client: Client object with request
            fetch_time: From when to fetch if first time, e.g. `3 days`
            incident_status: Incident statuses to fetch, can be: all, opened, closed, updated
            default_severity: Default incoming incident severity
            last_run: Last fetch object.
            max_fetch: maximum amount of incidents to fetch
            close_incident: Close respective Securonix incident.

        Returns:
            incidents, new last_run
        """
        timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        if not last_run:  # if first time running
            new_last_run = {
                "from": int(
                    arg_to_datetime(fetch_time, arg_name="First fetch time range").timestamp() * 1000  # type: ignore
                ),
                "to": int(datetime.now(tz=timezone.utc).timestamp() * 1000),
                "offset": 0,
            }
            demisto.debug(f"No last run object found, creating new last run object with value: {json.dumps(new_last_run)}")
        elif "time" in last_run:
            demisto.debug("Upgrading the last run object.")
            new_last_run = last_run
            new_last_run["from"] = date_to_timestamp(last_run.get("time"), date_format=timestamp_format)
            new_last_run["to"] = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
            new_last_run["offset"] = 0
            del new_last_run["time"]
        else:
            new_last_run = last_run
            demisto.debug("Using the last run object got from the previous run.")

        demisto_incidents: list = []

        from_epoch = new_last_run.get("from")
        to_epoch = new_last_run.get("to")
        offset = new_last_run.get("offset")
        demisto.info(f"Fetching Securonix incidents. From: {from_epoch}. To: {to_epoch}. Offset: {offset}")

        if incident_status.lower() == "all":
            incident_status = "updated"

        securonix_incidents = client.list_incidents_request(
            from_epoch=str(from_epoch),
            to_epoch=str(to_epoch),
            incident_status=incident_status,
            max_incidents=max_fetch,
            offset=str(offset),
        )

        if securonix_incidents:
            already_fetched: list[str] = new_last_run.get("already_fetched", [])  # type: ignore
            incident_items = securonix_incidents.get("incidentItems", [])

            for incident in incident_items:
                incident_id = str(incident.get("incidentId", 0))
                violator_id = str(incident.get("violatorId", 0))
                reasons = incident.get("reason", [])
                policy_list: list[str] = []
                policy_stages_json = {}
                policy_stages_table = []
                if isinstance(reasons, list):
                    for reason in reasons:
                        if isinstance(reason, str) and "PolicyType" in reason:
                            policy_type = reason.split(":")[-1].strip()
                            incident["policy_type"] = policy_type
                        if isinstance(reason, dict) and "Policies" in reason:
                            # Parse the policies.
                            policies = reason.get("Policies")
                            if not isinstance(policies, dict):
                                continue
                            policy_keys = list(policies.keys())
                            policy_keys.sort()
                            for stage_key in policy_keys:
                                stage_dict = policies.get(stage_key)
                                if not stage_dict or not isinstance(stage_dict, dict):
                                    continue
                                stage_name = list(stage_dict.keys())[0]
                                stage_policies: list[str] = stage_dict.get(stage_name)  # type: ignore
                                if not stage_policies or not isinstance(stage_policies, list):
                                    continue
                                stage_policies_str = ", ".join(str(policy) for policy in stage_policies)  # type: ignore
                                policy_list.extend(stage_policies)  # type: ignore
                                policy_stages_json[f"{stage_key}:{stage_name}"] = stage_policies  # noqa: E231
                                policy_stages_table.append(
                                    {"Stage Name": f"{stage_key}:{stage_name}", "Policies": stage_policies_str}  # noqa: E231
                                )

                if policy_list:
                    # Add the parsed policies to the incident.
                    incident["policy_list"] = list(dict.fromkeys(policy_list))
                    incident["policy_stages_json"] = policy_stages_json
                    incident["policy_stages_table"] = policy_stages_table

                if incident_id not in already_fetched:
                    incident.update(get_mirroring())

                    if close_incident:
                        incident["close_sx_incident"] = True
                    else:
                        incident["close_sx_incident"] = False

                    incident_name = get_incident_name(incident, incident_id, violator_id)

                    demisto_incidents.append(
                        {
                            "name": incident_name,
                            "occurred": timestamp_to_datestring(incident.get("lastUpdateDate")),
                            "severity": incident_priority_to_dbot_score(incident.get("priority"), default_severity),
                            "rawJSON": json.dumps(incident),
                        }
                    )

                    already_fetched.append(str(incident_id))

            # If incidents returned from API, then only update the offset value.
            if incident_items:
                new_offset = offset + len(incident_items)  # type: ignore
                new_from = from_epoch
                new_to = to_epoch
                demisto.debug(f"Updating the offset to {new_offset}.")
            # Else, reset the value of offset. From value would be the to_epoch of previous run.
            # And, To value would be current timestamp.
            else:
                new_offset = 0
                new_from = to_epoch
                new_to = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
                demisto.debug(f"Resetting the offset to 0. New From is {new_from}. New To is {new_to}.")

            new_last_run.update(
                {
                    "from": new_from,  # type: ignore
                    "to": new_to,  # type: ignore
                    "offset": new_offset,
                    "already_fetched": already_fetched,  # type: ignore
                }
            )

        demisto.setLastRun({"value": json.dumps(new_last_run)})

        demisto.info(f"Creating {len(demisto_incidents)} new incidents.")
        return demisto_incidents


    def fetch_securonix_threat(client: Client, fetch_time: str | None, tenant_name: str, max_fetch: str, last_run: dict) -> list:
        """Uses to fetch threats into Demisto.

        Args:
            client: Client object with request
            fetch_time: From when to fetch if first time, e.g. `3 days`
            tenant_name: Name of the tenant from which threat belongs to
            last_run: Last fetch object.
            max_fetch: maximum amount of incidents to fetch

        Returns:
            incidents, new last_run
        """
        timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        if not last_run:  # if first time running
            new_last_run = {
                "time": arg_to_datetime(fetch_time, arg_name="First fetch time range").strftime(  # type: ignore
                    timestamp_format
                )
            }
        else:
            new_last_run = last_run
        demisto_incidents: list = []
        from_epoch = date_to_timestamp(new_last_run.get("time"), date_format=timestamp_format)
        to_epoch = date_to_timestamp(datetime.now(), date_format=timestamp_format)
        # Get threats from Securonix
        demisto.info(f"Fetching Securonix Threats. From: {from_epoch}. To: {to_epoch}")

        offset = last_run.get("offset", 0)

        securonix_threats = client.list_threats_request(from_epoch, to_epoch, tenant_name, offset, max_fetch)  # type: ignore

        already_fetched = last_run.get("already_fetched", [])
        if securonix_threats:
            for threat in securonix_threats:
                threat_name = threat.get("threatname", "Securonix Threat")
                entity_id = threat.get("entityid", "")
                resource_name = threat.get("resourcename", "")
                resource_type = threat.get("resourcetype", "")
                resource_group_name = threat.get("resourcegroupname", "")
                policies = ", ".join(sorted(threat.get("policies", [])))

                if (entity_id, resource_name, resource_type, resource_group_name, policies) not in already_fetched:
                    incident_name = f"{threat_name}, Entity ID: {entity_id}"

                    demisto_incidents.append(
                        {
                            "name": incident_name,
                            "occurred": timestamp_to_datestring(threat.get("generationtime_epoch", datetime.now())),
                            "rawJSON": json.dumps(threat),
                        }
                    )
                    already_fetched.append((entity_id, resource_name, resource_type, resource_group_name, policies))

            new_last_run.update({"offset": offset + int(max_fetch), "already_fetched": already_fetched})
        else:
            now = datetime.now().strftime(timestamp_format)
            new_last_run.update({"offset": 0, "time": now})

        demisto.setLastRun({"value": json.dumps(new_last_run)})
        return demisto_incidents


    def get_incident_name(incident: dict, incident_id: str, violator_id: str) -> str:
        """Get the incident name by concatenating the incident reasons if possible

        Args:
            incident: incident details
            incident_id: the incident id
            violator_id: the violator id

        Returns:
            incident name.
        """
        incident_reasons = incident.get("reason", [])
        try:
            incident_reason = ""
            for reason in incident_reasons:
                if isinstance(reason, str):
                    if reason.startswith("Threat Model: "):
                        incident_reason += f"{reason[14:]}, "
                    if reason.startswith("Policy: "):
                        incident_reason += f"{reason[8:]}, "
            if incident_reason:
                # Remove ", " last chars and concatenate with the incident ID
                incident_name = f"{incident_reason[:-2]}: {incident_id}"
            else:
                incident_name = f"Securonix Incident {incident_id}, Violator ID: {violator_id}"
        except ValueError:
            incident_name = f"Securonix Incident: {incident_id}."

        return incident_name


    def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
        """Retrieve the IDs of the incidents which are updated since the last updated.

        Args:
            client: XSOAR client to use.
            args:
                lastUpdate: When was the last time we retrieved data.

        Returns:
            GetModifiedRemoteDataResponse: List of incidents IDs which are modified since the last update.
        """
        # Retrieve the arguments passed with the command.
        command_args = GetModifiedRemoteDataArgs(args)

        # Parse the last update date got from the command arguments.
        command_last_run_date = dateparser.parse(command_args.last_update, settings={"TIMEZONE": "UTC"})

        demisto.debug(f"Last update date of get-modified-remote-data command is {command_last_run_date}.")

        # Convert the datetime object to epoch as the API requires the time in epoch format.
        from_epoch_time = date_to_timestamp(command_last_run_date)
        # End time for the API call will be current time.
        to_epoch_time = date_to_timestamp(datetime.now(tz=timezone.utc))

        offset = 0
        len_of_incidents = 0
        updated_incident_ids = []

        while True:
            offset += len_of_incidents

            list_incidents_resp = client.list_incidents_request(
                from_epoch=str(from_epoch_time),
                to_epoch=str(to_epoch_time),
                incident_status="updated",
                max_incidents="500",
                offset=str(offset),
            )

            len_of_incidents = len(list_incidents_resp.get("incidentItems", []))

            if len_of_incidents == 0:
                break

            # Extract the IDs of the incidents.
            updated_incident_ids.extend([inc.get("incidentId") for inc in list_incidents_resp.get("incidentItems", [])])

            if len(updated_incident_ids) >= 10000:
                break

        # Filter out None values if there are any.
        updated_incident_ids: list[str] = list(filter(None, updated_incident_ids))

        # Filter out any duplicate incident IDs.
        updated_incident_ids = list(set(updated_incident_ids))

        # At max 10,000 incidents should be updated.
        updated_incident_ids = updated_incident_ids[:10000]

        demisto.debug(f"Number of incidents modified between {from_epoch_time} to {to_epoch_time} are {len(updated_incident_ids)}.")
        demisto.debug(f"List of modified incident ids between {from_epoch_time} to {to_epoch_time} is {updated_incident_ids}.")

        return GetModifiedRemoteDataResponse(updated_incident_ids)


    def get_remote_data_command(
        client: Client, args: dict[str, Any], close_states_of_securonix: list[str]
    ) -> Union[str, GetRemoteDataResponse]:
        """Return the updated incident and updated entries.

        Args:
            client: XSOAR client to use.
            args:
                id: Incident ID to retrieve.
                lastUpdate: When was the last time we retrieved data.
            close_states_of_securonix: List of Securonix incident states that can be considered as closed.

        Returns:
            Union[str, GetRemoteDataResponse]: first entry is the incident (which can be completely empty) and the new
                entries.
        """
        new_entries_to_return = []
        timestamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"

        sx_incident_id: str = args.get("id")  # type: ignore
        demisto.debug(f"Getting update for remote {sx_incident_id}.")

        command_last_run_dt = arg_to_datetime(arg=args.get("lastUpdate"), arg_name="lastUpdate", required=True)
        command_last_run_epoch = date_to_timestamp(command_last_run_dt, date_format=timestamp_format)
        demisto.debug(f"The time when the last time get-remote-data command is called for current incident is {command_last_run_dt}.")

        # Retrieve the latest incident data from the Securonix platform.
        remote_incident_data = client.get_incident_request(incident_id=sx_incident_id)
        remote_incident_data = remote_incident_data.get("incidentItems", [])
        remote_incident_data = remote_incident_data[0]

        if not remote_incident_data:
            return "Incident was not found."

        # Check the last modified date of the incident fetched.
        incident_last_update_dt = arg_to_datetime(
            arg=remote_incident_data.get("lastUpdateDate"), arg_name="lastUpdateDate", required=True
        )
        incident_last_update_epoch = date_to_timestamp(incident_last_update_dt, date_format=timestamp_format)

        if command_last_run_epoch > incident_last_update_epoch:
            demisto.debug(f"Nothing new in the Securonix incident {sx_incident_id}.")
        else:
            demisto.debug(f"The Securonix incident {sx_incident_id} is updated.")

        activity_history = client.get_incident_activity_history_request(incident_id=sx_incident_id)
        filtered_history_entries = filter_activity_entries_by_time(activity_history, timestamp=command_last_run_epoch)

        # Update the status of XSOAR incident.
        close_incident = argToBoolean(demisto.params().get("close_incident", False))

        # Skip closing of XSOAR if the close Securonix incident checkbox is checked.
        if not close_incident:
            if is_incident_closed_on_securonix(filtered_history_entries, close_states_of_securonix):
                demisto.debug(f"Closing the XSOAR incident as its respective Securonix incident {sx_incident_id} is closed.")
                close_comments = extract_closing_comments(filtered_history_entries, close_states_of_securonix)

                new_entries_to_return.append(
                    {
                        "Type": EntryType.NOTE,
                        "Contents": {"dbotIncidentClose": True, "closeNotes": close_comments, "closeReason": "Resolved"},
                        "ContentsFormat": EntryFormat.JSON,
                        "Note": True,
                    }
                )
            else:
                demisto.debug(f"Not closing the XSOAR incident as its respective Securonix incident {sx_incident_id} is still open.")

        # Update the comments.
        comment_entries = filter_comment_activity_entries(filtered_history_entries)

        for entry in comment_entries:
            comments_text = []
            comments_list = entry.get("comment", {})

            for _comment in comments_list:
                comments_text.append(_comment.get("Comments"))

            comments_text: list[str] = list(filter(None, comments_text))

            if "Mirrored From XSOAR" in ", ".join(comments_text):
                demisto.debug("Skipping the comment as it is mirrored from XSOAR.")
                continue

            new_entries_to_return.append(
                {
                    "Type": EntryType.NOTE,
                    "Contents": f"[Mirrored From Securonix]\n"
                    f"Added By: {entry.get('username')}\n"
                    f"Added At: {entry.get('eventTime')} UTC\n"
                    f"Comment Content: {', '.join(comments_text)}",
                    "ContentsFormat": EntryFormat.TEXT,
                    "Note": True,
                }
            )

        # Update the attachments.
        attachment_entries = filter_attachment_activity_entries(filtered_history_entries)
        attachment_names = extract_names_of_attachments_from_entries(attachment_entries)

        if attachment_entries:
            attachment_file_entries = get_incident_attachments(client, {}, incident_id=sx_incident_id)

            # Removing the first entry from the response, as it is CommandResults.
            for xsoar_file_entry in attachment_file_entries:
                if isinstance(xsoar_file_entry, CommandResults):
                    continue

                if xsoar_file_entry.get("File", "") in attachment_names:
                    new_entries_to_return.append(xsoar_file_entry)

        return GetRemoteDataResponse(remote_incident_data, new_entries_to_return)


    def create_xsoar_to_securonix_state_mapping(params: dict[str, Any]) -> CommandResults:
        """Create a mapping of Securonix status and action with XSOAR's states.

        Args:
            params: The configuration parameters got from demisto.params()

        Returns:
            CommandResults: Standard CommandResults object.
        """
        global XSOAR_TO_SECURONIX_STATE_MAPPING

        active_state_action = params.get("active_state_action_mapping", "").strip()
        active_state_status = params.get("active_state_status_mapping", "").strip().lower()

        close_state_action = params.get("closed_state_action_mapping", "").strip()
        close_state_status = params.get("closed_state_status_mapping", "").strip().lower()

        XSOAR_TO_SECURONIX_STATE_MAPPING["ACTIVE"] = {"action": active_state_action, "status": active_state_status}

        XSOAR_TO_SECURONIX_STATE_MAPPING["DONE"] = {"action": close_state_action, "status": close_state_status}

        hr_table = [
            {
                "XSOAR Status": "Active",
                "Securonix Status": XSOAR_TO_SECURONIX_STATE_MAPPING["ACTIVE"]["status"],
                "Securonix Action Name": XSOAR_TO_SECURONIX_STATE_MAPPING["ACTIVE"]["action"],
            },
            {
                "XSOAR Status": "Closed",
                "Securonix Status": XSOAR_TO_SECURONIX_STATE_MAPPING["DONE"]["status"],
                "Securonix Action Name": XSOAR_TO_SECURONIX_STATE_MAPPING["DONE"]["action"],
            },
        ]

        human_readable = tableToMarkdown(
            "State Mapping:", t=hr_table, headers=["XSOAR Status", "Securonix Status", "Securonix Action Name"], removeNull=True
        )

        return CommandResults(
            outputs_prefix="Securonix.StateMapping",
            outputs=XSOAR_TO_SECURONIX_STATE_MAPPING,
            readable_output=human_readable,
            raw_response=XSOAR_TO_SECURONIX_STATE_MAPPING,
        )


    def update_remote_system(client: Client, args: dict[str, Any]) -> str:
        """This command pushes local changes to the remote incident.

        Args:
            client (Client): XSOAR Client to use.
            args (Dict[str, Any]):
                args['data']: The data to send to the remote system.
                args['entries']: The entries to send to the remote system.
                args['incident_changed']: Boolean telling us if the local incident indeed changed or not.
                args['remote_incident_id']: The remote incident id.

        Returns:
            str: The remote incident ID.
        """
        parsed_args = UpdateRemoteSystemArgs(args)
        remote_incident_id = parsed_args.remote_incident_id
        xsoar_incident_id = parsed_args.data.get("id", "")
        new_entries = parsed_args.entries

        if new_entries:
            for entry in new_entries:
                demisto.debug(f"Sending the entry with ID: {entry.get('id')} and Type: {entry.get('type')}")

                entry_content = entry.get("contents", "")
                entry_user = entry.get("user", "dbot") or "dbot"

                comment_str = (
                    f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\nAdded By: {entry_user}\nComment: {entry_content}"
                )
                client.add_comment_to_incident_request(remote_incident_id, comment_str)

        close_incident = parsed_args.data.get("securonixcloseincident", False)

        if not close_incident and parsed_args.incident_changed and parsed_args.inc_status == IncidentStatus.DONE:
            delta_keys = parsed_args.delta.keys()
            if "closingUserId" not in delta_keys and "closeReason" not in delta_keys:
                return remote_incident_id

            close_notes = parsed_args.delta.get("closeNotes", "")
            close_reason = parsed_args.delta.get("closeReason", "")
            close_user_id = parsed_args.delta.get("closingUserId", "")

            closing_comment = (
                f"[Mirrored From XSOAR] XSOAR Incident ID: {xsoar_incident_id}\n"
                f"Closed By: {close_user_id}\nClose Reason: {close_reason}\nClose Notes: {close_notes}"
            )
            demisto.debug(f"Closing Comment: {closing_comment}")

            client.perform_action_on_incident_request(
                incident_id=remote_incident_id, action=XSOAR_TO_SECURONIX_STATE_MAPPING["DONE"]["action"], action_parameters=""
            )
            client.add_comment_to_incident_request(incident_id=remote_incident_id, comment=closing_comment)

        return remote_incident_id


    def main():
        """
        PARSE AND VALIDATE INTEGRATION PARAMS
        """
        params = demisto.params()
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
        create_xsoar_to_securonix_state_mapping(params)

        command = demisto.command()
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
                validate_mirroring_parameters(params=params)

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

    register_module_line('Securonix', 'end', __line__())
  subtype: python3
  type: python
  nativeimage:
  - '8.8'
  - '8.6'
tests:
- No test - no instance
fromversion: 5.0.0
image: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHgAAAAyCAYAAACXpx/YAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAABHlJREFUeNrsWT1yE0sQFpQzkr0B6xMgn8Cr+FWBHBJZewKk9CV6TkgtTiApIpShiljrE7CcgOUEbEJOt+trVXve7I8sG1PwfVVTWq26Z3r6Z7qnNRgQBEEQBEEQBEEQBEEQBEEQBEEQRBOeUAW/Hj/+TRP52MiYPXtblQ+51lOq+1EwkZHJWD70QjTw42Alo9IIpioIgjigyHr5YjGWjzfIGR5aHHzQ4+bjl2nl6LWAmMo4l5E6eqVZC+1/kTVaeWQshK8G7QR0OteqQeZL+RjqESg0pXunuMBap6A5E5oCNJnbaxLZ604O0Cv/JWRUuV9hTo8ryFHF+GwPePfZZIzpKdjjErlc5Tnx8/fOwdjwBhvWiQqMGhuZyxgHhtriferoC3yfC802YlzPY+tUxqMbFzozfAp50hbRhxEjDWHYr5jz1u9wnC32k8Co4V63kNeQuGJp7oxbOJox5h1E+HZ7gCPm+DpHYDXZZQLjDuCgVRPtUUcAv7GiQCbJg0V0M+fyfuFeW+SU4cIwkG40U8exqHE8tY8m52D6e9m2iT2RwADvZM4rJ9ulK4BmQaSao5uTxKKrBF8ov+45VYPZek3QaBa6UxhvKc+VnUCB3q36vrXeXapo89Z1RBhV+iyIRDsyRqFB8P0CX7OAZwCeIuApZJyEznUgVO5RoGyLWl0v98Y1OdT5AqcPkcfkh8MMIkd3k5FzOEsCIyeR086CbnHoNcmMdB4cTU3H4gBKqjvmOw14ytBTHxDvIu9Omxw5MJbKnyCKbu2rRf5vd5Bx5FODNkbQHFm69NHrinXUQxljRNlENqabvLb81GBIVUBTgfC8Kap+YWFZtZxUVQ/eNMjtffj2gupVdDhCtK7xWcIeGVJZfXCjA145wjFTY/I58tF3reQikW00sTG5Ry//owHdX7z/Z2En3VieK9QOvR3qqOdCmhdyFCNqwBcW1fDms6BLs+6Ytu4Z2X8tcK2bvv40VSOr/mt51vw/ld/qPvm3l4EjhZLd27Rg+u6vSXaN6arsWvL3Y6F2V7A2pA0Oet/GnaBavzn+n72toPPd+pdCU/bR89MDjpC6IY9mPQoyX7jcGBhXin1y6PMuQ+zhaNdWTHb0BG7u6Q9ZELomyACNlZXT18JV5RvXG7ibgbUpgTw7bPCyncJhcFt8G1tceWR8DebzAmehUmV8RtcmdKSJk2F3jcDRlu5Z+OxqDOH/n+KwzqalCr8v49rfiHZli1XKM3eN2nQF01GHJ1lHSJVZO+Wm7rhaB4sbnxqydMdZFhRiZYRHHcM6QcOg05SoE2n0yPPKNQOWoE+Co/5iz6p1hmuIppyxk93LUXS1EA/ExjnnWYusZ2hrWrTne0cwjqFjGKBwhslcNyj3G0YUjxzP0PGUiJRjXyDAaCeOp3bOYGuc+JSAZkAe0A+hmCs0TVaRFFI05U/QH0PG0snu5RhFcnfRcc2rXOs15KuCgLqGY7Zeg1ALjUD7rc9RTRAEQRAEQRAEQRAEQRAEQRAEQRAEQRAEQfwu+CnAAPmMMnD4LyNcAAAAAElFTkSuQmCC
detaileddescription: "### Partner Contributed Integration\n#### Integration Author: Securonix\nSupport and maintenance for this integration are provided by the author. Please use the following contact details:\n- **Email**: [support@securonix.com](mailto:support@securonix.com)\n- **URL**: [https://www.securonix.com](https://www.securonix.com)\n***\n### Securonix Integration\nUse Securonix Integration to identify and prioritize Security Incidents and Threats across the organization. This integration allows the security teams to synchronize the Securonix Incidents and Threats with Cortex XSOAR in real time making it feasible to manage operations from a single place.  \n\nThis integration supports both cloud and on-prem v6.4 Feb 2023 R3 instances of Securonix.\n- To configure a cloud base instance use the *Tenant* parameter only.\n- To configure an on-prem instance, use both the *Host* and *Tenant* parameters.\n\n\n### Instance Configuration\nThe integration supports two types of ingestion:\n1. Securonix Incident: Fetches Securonix Incident as an XSOAR Incident\n2. Securonix Threat: Fetches Securonix Threat as an XSOAR Incident\n\n\n#### Securonix Incident\n\nTo fetch Securonix Incident follow the next steps:\n1. Select Fetches incidents.\n2. Under Classifier, select \"N/A\".\n3. Under Incident type, select \"Securonix Incident\".\n4. Under Mapper (incoming), select \"Securonix Incident - Incoming  Mapper\" for default mapping.\n5. Under Type of entity to fetch, select \"Incident\".\n6. Enter the connection parameters. (Host, Tenant, Username & Password)\n7. Select the \"Incidents to fetch\":\n    1. all - This will fetch incidents updated in the given time range. \n    2. opened - This will fetch incidents created in the given time range.\n    3. closed - This will fetch incidents closed in the given time range.\n8. Update \"Set default incident severity\", \"First Fetch time range\" & \"Max Fetch Count\" based on your requirement.\n9. Select the Incident Mirroring Direction:\n    1. Incoming - Mirrors changes from the Securonix incident into the Cortex XSOAR incident.\n    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Securonix incident.\n    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.\n    4. None - Turns off incident mirroring.\n10. Enter the relevant values for \"State\" & \"Action\" values for mirroring.\n     - Below table indicates which fields are required for the respective mirroring type.\n\n| **Mirroring Type** | **Securonix workflow States for Incoming mirroring** | **Securonix State for XSOAR Active State** | **Securonix Action for XSOAR Active Action** | **Securonix State for XSOAR Closed State** | **Securonix Action for XSOAR Closed Action** | \n| --- | --- | --- | --- | --- | --- | \n| Incoming | Yes | No | No | No | No | \n| Outgoing | No | Yes | Yes | Yes | Yes | \n| Incoming and Outgoing | Yes | Yes | Yes | Yes | Yes |\n \n10. Enter the relevant Comment Entry Tag.  \n**Note**: This value is mapped to the **dbotMirrorTags** incident field in Cortex XSOAR, which defines how Cortex XSOAR handles comments when you tag them in the War Room. This is required for mirroring comments from Cortex XSOAR to Securonix.\n11. Optional: Check the \"Close respective Securonix incident after fetching\" parameter, if you want to close the Securonix Incident once it is fetched in the XSOAR.\n    Below Parameters are required if this option is checked:\n    - Securonix action name for XSOAR's active state for Outgoing\n    - Securonix status for XSOAR's active state for Outgoing\n    - Securonix action name for XSOAR's close state for Outgoing\n    - Securonix status for XSOAR's close state for Outgoing\n12. Enter the relevant values for Securonix Retry parameters \"Count\", \"Delay\" & \"Delay Type\".\n\n**Notes for mirroring:**\n\n- The mirroring settings apply only for incidents that are fetched after applying the settings. Pre-existing comments are not fetched/mirrored at the time of incident creation.\n- For mirroring to work flawlessly, a three-state workflow(similar to XSOAR) must be configured on the Securonix Incident side.\n- The mirroring is strictly tied to Incident type \"Securonix Incident\" & Incoming mapper \"Securonix Incident - Incoming Mapper\" if you want to change or use your custom incident type/mapper then make sure changes related to these are present.\n- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, dbotMirrorTags and securonixcloseincident.\n- To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. If you detach the out-of-the-box mapper and make changes to it, the pack does not automatically get updates.\n- If you are using a custom incident type, you also need to create custom corresponding incoming mappers.\n- Following new fields are introduced in the response of the incident to enable the mirroring:\n  - **mirror_direction**: This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.\n  - **mirror_tags**: This field determines what would be the tag needed to mirror the XSOAR entry out to Securonix. It is a required field for XSOAR to enable mirroring support.\n  - **mirror_instance**: This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.\n  - **close_sx_incident**: This field determines whether to close the respective Securonix incident once fetched in the XSOAR based on the instance configuration. It is required for closing the respective incident on Securonix. This will be used in the playbook to close the securonix incident.\n\n\n\n#### Securonix Threat\nTo fetch Securonix Threat follow the next steps:\n1. Select Fetches incidents.\n2. Under Classifier, select \"N/A\".\n3. Under Incident type, select Securonix Threat.\n4. Under Mapper (incoming), select Securonix Threat - Incoming Mapper for default mapping.\n5. Under Type of entity to fetch, select Threat.\n6. Enter the Tenant Name in case of MSSP user.\n7. Enter the connection parameters. (Host, Tenant, Username & Password)\n8. Enter the \"The maximum number of incidents to fetch each time\". The recommended number of threats to fetch is 100 considering the API implications, although 200 is allowed.\n9. Enter the relevant values for Securonix Retry parameters \"Count\", \"Delay\" & \"Delay Type\".\n\n\n---\n[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/securonix)"
signature: jyRoxrdD+oGYR+qVx+6LS10svQZgr0Il7/vIq8wr4OzkxyZxFXCB+bj7Y2+InuUqu1cA6wFLzb4idkzGPeTvKDFi6dW9bobA/0//3eKQIcNe4bZE+wAK46m+CIEQcgae7LZccU9hklMCtPaumVob8XEBsCN9KfYKZIIKTZRmI9YsIL/IQXx8VD8HVfE451IE0Z3G+k1cDssUIDuffgvkQfGcgDzJVaOzyLH4OQCWDNXNHAEz+TcfbLc0oT4jYfcuqQpkmNQjlW4UwoRzXcjAZ2JI2KYBbscAvpBdGjeuN5ZXa8gQel9dQ3Cg/CrDwJ4NOEX38he/WqzmYjGVEmNQaQ==
