package reconcile

// HimmelblauKey exposes the embedded repository key to the external tests.
func HimmelblauKey() []byte { return himmelblauKey }

// PackageCommand exposes the process-group runner of apt-get and dpkg.
var PackageCommand = packageCommand
