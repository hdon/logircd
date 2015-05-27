# logircd
An IRC server based on [vibe-d](http://vibed.org/).

I primarily wanted to use this at work for intra-office communication, so some of its functionality is limited. Please see Caveats below.

## Channel modes supported
* `+a` anonymous channel
* `+b` ban
* `+e` ban exception
* `+h` half-op
* `+i` invite-only channel
* `+m` moderated
* `+o` operator
* `+s` secret
* `+t` topic-locked
* `+v` voice

## User modes supported
* `+i` invisible
* `+o` server operator
* `+w` receive wallops
* `+s` receive server notices

## Commands supported
* `NICK` change nick
* `USER` set user info
* `TOPIC` set or get channel topic
* `MODE` retrieve or set user or channel modes
* `AWAY` set or unset AWAY status
* `KICK` remove user from channel
* `ISON` query if user is connected
* `PART` leave channel
* `INVITE` invite user to channel
* `JOIN` join channel
* `PRIVMSG` send message to user or channel
* `PING` ping server
* * `QUIT` part all channels and disconnect
* `LIST` list users in channel
* `WHO` list users connected to server
* `WHOIS` get info on a particular user

## Caveats
A few commands don't implement all possible invocations as described by RCFs 1459 and 2812.

The server does not form a network with other servers. This is why you don't see commands like SQUIT.

The server doesn't support host bans with KLINE or disconnecting a user with KLINE yet, nor any kind of flood control.
