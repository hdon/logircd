module logircd;
import vibe.d;
import std.array;
import std.string;
import core.stdc.ctype;

class User {
  TCPConnection conn;
  uint iid;
  bool loggedin;
  string nick;
  string username;
  string hostname;
  string servername;
  string realname;
  Channel[string] channels;
  this(TCPConnection conn, uint iid) {
    this.conn = conn;
    this.iid = iid;
    this.nick = "*";
  }
  void partAll() {
    foreach (chan; channels)
      chan.part(this);
  }
  static if (0)
  string snick() {
    return loggedin ? nick : "*";
  }
}

class Channel {
  string name;
  string topic;
  User[uint] users;
  this(string name) {
    this.name = name;
    this.topic = "no topic set";
  }
  void join(User user) {
    users[user.iid] = user;
    user.channels[name] = this;
  }
  void part(User user) {
    if (user.iid in users)
      users.remove(user.iid);
    /* else TODO */
  }
}

string coerceAscii(string s) {
  char[] r;
  r.reserve(s.length);
  foreach (c; s)
    if (c == '\\')
      r ~= "\\\\";
    else if (c >= ' ' && c < 127)
      r ~= c;
    else
      r ~= format("\\x%02x", c);
  return cast(string) r;
}

shared static this() {
  int iidCounter = 0;
  string hostname = "127.0.0.1";
  string srvCmdFmt = ":logircd %s %s :%s\r\n";
  logircd.Channel[string] channels;
  User[string] usersByNick;
  User[uint] usersByIid;

  listenTCP(6667, (conn) {
    logInfo("New client!");
    auto user = new User(conn, iidCounter);
    usersByIid[iidCounter] = user;
    iidCounter++;
    bool quit = false;

    void tx(string s) {
      logInfo(format("--> %s", s.stripRight));
      conn.write(s);
    }
    void txAll(string s) {
      logInfo(format("==> %s", s.stripRight));
      foreach (user; usersByIid)
        user.conn.write(s);
    }

    void sendMessage(string cmd, string msg) {
      tx(format(srvCmdFmt, cmd, user.nick, msg));
    }

    sendMessage("NOTICE", "*** Welcome to the server!");

    auto rtask = runTask({
      while (!quit && conn.connected) {
        auto line = cast(string) conn.readLine(4096, "\r\n");
        if (line.length == 0)
          continue;
        logInfo(format("<-- %d bytes: %s", line.length, line));
        auto words = split(line);
        switch (words[0]) {
          case "CAP":
            if (words.length == 2 && words[1] == "LS")
              tx(format(":%s CAP %s LS :account-notify away-notify userhost-in-names\r\n", hostname, user.nick));
            break;
          case "NICK":
            if (words.length < 2)
            {
              tx(format(":%s 431 :No nick given.\r\n", hostname));
            }
            else if (words[1] in usersByNick)
            {
              tx(format(":%s 433 %s :Nick already in use.\r\n", hostname, words[1]));
            }
            else
            {
              if (user.nick in usersByNick)
                usersByNick.remove(user.nick);
              usersByNick[words[1]] = user;
              txAll(format(":%s!%s@%s NICK %s\r\n", user.nick, user.username, user.hostname, words[1]));
              user.nick = words[1];
              sendMessage("NOTICE", format("*** You are now known as %s", user.nick));
            }
            break;
          case "USER":
            /* TODO parse this correctly (look for the colon) */
            if (words.length < 5 || words[4][0] != ':')
            {
              logInfo("    malformed USER command TODO handle this");
            }
            else
            {
              user.username   = words[1];
              user.hostname   = words[2];
              user.servername = words[3];
              user.realname   = words[4][1..$] ~ join(words[5..$], " ");
              user.loggedin   = true;
              tx(format(":%s 001 %s :Welcome to LogIRCd, %s!%s@%s\r\n", hostname, user.nick, user.nick, user.username, user.hostname));
              tx(format(":%s 002 %s :Your host is %s, running LogIRCd version 0.0.0\r\n", hostname, user.nick, hostname));
              tx(format(":%s 003 %s :This server was created Sat Jul 5 2014 at 23:39:00 EDT\r\n", hostname, user.nick));
              tx(format(":%s 004 %s %s 0.0.0 a aioOw abehiIklmnostv\r\n", hostname, user.nick, hostname));
              tx(format(":%s 251 %s :There are %d users and 0 invisible on 1 servers\r\n", hostname, user.nick, usersByIid.length));
              tx(format(":%s 252 %s 0 :operator(s) online\r\n", hostname, user.nick));
              tx(format(":%s 372 %s :This is the message of the day!\r\n", hostname, user.nick));
              tx(format(":%s!%s@%s MODE %s +x\r\n", user.nick, user.username, user.hostname, user.nick));
              // TODO
            }
            break;
          case "PART":
            if (words.length < 2)
              { /* TODO */ }
            else {
              if (words[1] !in channels)
                { /* TODO */ }
              else {
                channels[words[1]].part(user);
              }
            }
            break;
          case "JOIN":
            if (!user.loggedin)
              /* TODO */
              break;
            if (words.length != 2)
              { /* TODO */ }
            else {
              if (words[1] !in channels)
                channels[words[1]] = new logircd.Channel(words[1]);
              auto channel = channels[words[1]];
              txAll(format(":%s!%s@%s JOIN %s\r\n", user.nick, user.username, user.hostname, channel.name));
              tx(format(":%s 332 %s %s :%s\r\n", hostname, user.nick, channel.name, channel.topic));
              tx(format(":%s 333 %s %s voxel!voxel@host86-175-172-11.range86-175.btcentralplus.com 1425226259\r\n", 
                hostname, user.nick, channel.name));
              channel.join(user);
              foreach (cuser; channel.users)
              tx(format(":%s 353 %s @ %s :%s\r\n", hostname, user.nick, channel.name, cuser.nick));
              tx(format(":%s 366 %s %s :End of /NAMES list.\r\n", hostname, user.nick, channel.name));
              // TODO send 333?

            }
            break;
          case "PRIVMSG":
            if (words.length < 3)
            { /* TODO */ }
            else {
              txAll(format(":%s!%s@%s PRIVMSG %s :%s\r\n", user.nick, user.username, user.hostname, words[1],
                words[2][1..$] ~ join(words[3..$])));
            }
            break;
          case "PING":
            /* Only implementing PING from client. xchat2 doesn't send PING spuriously, it seems,
             * but irssi does, and disconnects after 301 seconds on my system. Also, we assume that
             * we are the one being pinged! XXX */
            if (words.length == 2) {
              /* This is how AfterNET responded... XXX TODO */
              tx(format(":%s PONG %s :%s\r\n", words[1], words[1], words[1]));
            }
            break;
          //case "LIST":
            //if (words.length == 1)
            //break;
          default:
            break;
        }
      }
    });

    rtask.join;

    if (conn.connected)
      conn.close;

    user.partAll;
    usersByIid.remove(user.iid);
    usersByNick.remove(user.nick);
    logInfo(":::Reached end of connection control scope");
  });

  logInfo("Please connect via irc client.");
}
