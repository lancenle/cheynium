sudo vi /etc/logrotate.d/cheynium

/home/default/cheynium/logs/*.log {
  rotate 60
  daily
  compress
  missingok
  notifempty
}
