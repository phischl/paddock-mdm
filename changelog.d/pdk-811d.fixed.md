- A user's withdrawal of a software request now takes effect whatever order the server processes the device's reports
  in: a request withdrawn before the server processed it no longer opens and can no longer be approved, and a request
  the user sent again after a withdrawal stays open. `device.software_request_withdrawn` gains the param `closed`
  (whether the withdrawal closed an open request).
