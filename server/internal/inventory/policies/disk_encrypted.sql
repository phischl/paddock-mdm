-- The root file system is on dm-crypt (LUKS): passes when osquery reports the device mounted on / as encrypted.
SELECT 1 FROM mounts m JOIN disk_encryption de ON m.device_alias = de.name WHERE m.path = '/' AND de.encrypted = 1;
