- Software requests: when a user withdraws a pending request in the desktop app, the server now closes the request as
  *Withdrawn*, so administrators no longer see it as waiting and cannot approve a request the user no longer wants.
  The audit log records the withdrawal as `device.software_request_withdrawn` (syslog MSGID
  `device.sw_request_withdrawn`). Agents report a withdrawal only to a server that announces support for it in the
  device's bundle; with an older server the withdrawal stays on the device as before.
