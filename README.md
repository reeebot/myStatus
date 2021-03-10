# myStatus
### v.PUSH
#### status light app for Pimoroni Blinkt! hat
http://docs.pimoroni.com/blinkt/
<br>

<br>
<img src="https://i.imgur.com/Fht4NHv.png">

## Install
...

<br>

## Service

```
sudo cp myStatus.service /etc/systemd/system/myStatus.service
```

Testing the service:

```
sudo systemctl start myStatus.service
sudo systemctl stop myStatus.service
sudo systemctl status myStatus.service
```

Enable/disable for startup:

```
sudo systemctl enable myStatus.service
sudo systemctl disable myStatus.service
```
