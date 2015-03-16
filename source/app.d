module logircd;
import vibe.d;
import std.array;
import std.string;
import core.stdc.ctype;

class User {
  TCPConnection conn;
  bool loggedin;
  string nick;
  string username;
  string hostname;
  string servername;
  string realname;
  Channel[string] channels;
  Task rtask, wtask;
  /* lastSentMessageId is used to make it easier to send a message to the union set
   * of groups of users (mostly, users in channels.)
   */
  uint lastSentMessageId;
  uint iid;
  this(TCPConnection conn, uint iid) {
    this.conn = conn;
    this.iid = iid;
    this.nick = "*";
  }
  void send(string msg) {
    logInfo(format("(server) -> (%s)\t%s", nick, msg.stripRight));
    wtask.send(msg);
  }
  void partAll() {
    foreach (chan; channels)
      chan.part(this);
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
  int sentMessageCounter;
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

    void sendMessage(string cmd, string msg) {
      user.send(format(srvCmdFmt, cmd, user.nick, msg));
    }

    user.rtask = runTask({
      while (!quit && conn.connected) {
        auto line = cast(string) conn.readLine(4096, "\r\n");
        if (line.length == 0)
          continue;
        logInfo(format("(server) <- (%s)\t %s", user.nick, line));
        auto words = split(line);
        switch (words[0]) {
          case "CAP":
            if (words.length == 2 && words[1] == "LS")
              user.send(format(":%s CAP %s LS :account-notify away-notify userhost-in-names\r\n", hostname, user.nick));
            break;
          case "NICK":
            if (words.length < 2)
            {
              user.send(format(":%s 431 :No nick given.\r\n", hostname));
            }
            else if (words[1] in usersByNick)
            {
              user.send(format(":%s 433 %s :Nick already in use.\r\n", hostname, words[1]));
            }
            else
            {
              if (user.nick in usersByNick)
                usersByNick.remove(user.nick);
              usersByNick[words[1]] = user;
              auto msg = format(":%s!%s@%s NICK %s\r\n", user.nick, user.username, user.hostname, words[1]);
              sentMessageCounter++;
              user.send(msg);
              user.lastSentMessageId = sentMessageCounter;
              foreach (channel; user.channels)
              {
                foreach (cuser; channel.users)
                {
                  if (cuser.lastSentMessageId != sentMessageCounter)
                  {
                    cuser.lastSentMessageId = sentMessageCounter;
                    cuser.send(msg);
                  }
                }
              }
              user.nick = words[1];
              //sendMessage("NOTICE", format("*** You are now known as %s", user.nick));
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
              /* TODO check for colon? */
              user.realname   = line[words[4].ptr - line.ptr + 1 .. $];
              user.loggedin   = true;
              user.send(format(":%s 001 %s :Welcome to LogIRCd, %s!%s@%s\r\n",
                hostname, user.nick, user.nick, user.username, user.hostname));
              user.send(format(":%s 002 %s :Your host is %s, running LogIRCd version 0.0.0\r\n",
                hostname, user.nick, hostname));
              user.send(format(":%s 003 %s :This server was created Sat Jul 5 2014 at 23:39:00 EDT\r\n",
                hostname, user.nick));
              user.send(format(":%s 004 %s %s 0.0.0 a aioOw abehiIklmnostv\r\n",
                hostname, user.nick, hostname));
              user.send(format(":%s 251 %s :There are %d users and 0 invisible on 1 servers\r\n",
                hostname, user.nick, usersByIid.length));
              user.send(format(":%s 252 %s 0 :operator(s) online\r\n", hostname, user.nick));
              user.send(format(":%s 372 %s :This is the message of the day!\r\n", hostname, user.nick));
              user.send(format(":%s!%s@%s MODE %s +x\r\n", user.nick, user.username, user.hostname, user.nick));
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
              /* Broadcast JOIN message */
              auto channel = channels[words[1]];
              auto msg = format(":%s!%s@%s JOIN %s\r\n", user.nick, user.username, user.hostname, channel.name);
              channel.join(user);
              foreach (cuser; channel.users)
                cuser.send(msg);
              /* 332 topic */
              user.send(format(":%s 332 %s %s :%s\r\n", hostname, user.nick, channel.name, channel.topic));
              /* 333 topic set */
              user.send(
                format(":%s 333 %s %s voxel!voxel@host86-175-172-11.range86-175.btcentralplus.com 1425226259\r\n", 
                hostname, user.nick, channel.name));
              auto cuserstr = cast(string) join(map!"a.nick"(channel.users.values), " ");
              user.send(format(":%s 353 %s @ %s :%s\r\n", hostname, user.nick, channel.name, cuserstr));
              foreach (cuser; channel.users)
              {
                /* WHO response
                user.send(format(":%s 352 %s %s %s %s %s %s Hx :0 %s\r\n"
                , hostname
                , user.nick
                , channel.name
                , cuser.username
                , cuser.hostname
                , hostname // TODO?
                , cuser.nick
                , cuser.realname
                ));*/
              }
              user.send(format(":%s 366 %s %s :End of /NAMES list.\r\n", hostname, user.nick, channel.name));
              /* WHO response
              user.send(format(":%s 315 %s %s :End of /WHO list.\r\n", hostname, user.nick, channel.name));
              */
            }
            break;
          case "PRIVMSG":
            if (words.length < 3)
            { /* TODO */ }
            else {
              if (words[1] in usersByNick)
                usersByNick[words[1]].send(format(":%s!%s@%s PRIVMSG %s :%s\r\n",
                  user.nick, user.username, user.hostname, words[1], line[words[2].ptr - line.ptr + 1 .. $]));
              else if (words[1] in channels)
                foreach (cuser; channels[words[1]].users)
                  if (cuser !is user)
                    cuser.send(format(":%s!%s@%s PRIVMSG %s :%s\r\n",
                      user.nick, user.username, user.hostname, words[1], line[words[2].ptr - line.ptr + 1 .. $]));
            }
            break;
          case "PING":
            /* Only implementing PING from client. xchat2 doesn't send PING spuriously, it seems,
             * but irssi does, and disconnects after 301 seconds on my system. Also, we assume that
             * we are the one being pinged! XXX */
            if (words.length == 2) {
              /* This is how AfterNET responded... XXX TODO */
              user.send(format(":%s PONG %s :%s\r\n", words[1], words[1], words[1]));
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

    user.wtask = runTask({
      while (!quit && conn.connected) {
        receive((string s) {
          conn.write(s);
        });
      }
    });

    sendMessage("NOTICE", "*** Welcome to the server!");

    scope(exit)
    {
      user.partAll;
      if (conn.connected)
        conn.close;
      usersByIid.remove(user.iid);
      usersByNick.remove(user.nick);
    }

    user.rtask.join;
    user.wtask.join;

    logInfo(":::Reached end of connection control scope");
  });

  logInfo("Please connect via irc client.");
}
