module logircd;
import vibe.d;
import std.array;
import std.string;
import core.stdc.ctype;
import numerics;

immutable string serverHostname;
immutable string serverMessagePrefix;
enum softwareFullname = "logircd 0.0.0";

class User {
  enum MODE_a = 1;
  enum MODE_i = 2;
  enum MODE_w = 4;
  enum MODE_r = 8;
  enum MODE_o = 16;
  enum MODE_O = 32;
  enum MODE_s = 64;

  TCPConnection conn;
  bool loggedin;
  string nick;
  string username;
  string hostname;
  string servername;
  string realname;
  UserChannel[string] channels;
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
      chan.chan.part(this);
  }

  static bool validateNick(string s) {
    /* RFC 2812 Section 2.3.1 */
    /* i made up the < 3 part */
    if (s.length < 3 && s.length > 9)
      return false;
    if (!(s[0].isalpha || (s[0] >= 0x5B && s[0] <= 0x60) || (s[0] >= 0x7B && s[0] <= 0x7D)))
      return false;
    foreach (c; s[1..$]) {
      if (!(c.isalpha || c.isdigit || c == '-' || (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7D)))
        return false;
    }
    return true;
  }
}

class Channel {
  string name;
  string topic;
  string topicWhoTime;
  string[] bans;

  /* Boolean channel modes */
  enum MODE_n = 0x00000001;    /* NO_EXTERNAL_MSGS */
  enum MODE_t = 0x00000002;    /* TOPIC_LOCK */
  enum MODE_s = 0x00000004;    /* SECRET */
  enum MODE_i = 0x00000008;    /* INVITE */
  enum MODE_m = 0x00000010;    /* MODERATED */
  uint bmodes;

  UserChannel[uint] users;

  this(string name) {
    this.name = name;
  }
  UserChannel join(User user) {
    return
    user.channels[name] =
    users[user.iid] =
      new UserChannel(user, this);
  }
  void part(User user) {
    if (user.iid in users)
      users.remove(user.iid);
    /* else TODO */
  }

  void setBooleanMode(User actor, uint mode, bool on)
  {
    if (actor.iid !in users)
    {
      actor.txsn!"442 %s %s :You're not in that channel."(name);
      return;
    }

    bmodes &= ~mode;
    if (on)
      bmodes |= mode;
  }

  void setTopic(User author, string topic) {
    this.topic = topic;
    topicWhoTime = format("%s!%s@%s %d", author.nick, author.username, author.hostname, core.stdc.time.time(null));

    /* Broadcast new topic */
    foreach (user; users) {
      /* 332 RPL_TOPIC */
      user.user.send(format(":%s 332 %s %s :%s\r\n", serverHostname, user.user.nick, name, topic));
      /* 333 RPL_TOPICWHOTIME */
      user.user.send(format(":%s 333 %s %s %s\r\n", serverHostname, user.user.nick, name, topicWhoTime));
    }
  }
  string names() {
    return cast(string) std.array.join(map!((UserChannel uc){
      return format("%s%s", uc.channelOperator?"@":"", uc.user.nick);
    })(users.values), " ");
  }

  string modeString() {
    char[32] buf;
    size_t i;
    buf[i++] = '+';
    if (bmodes & MODE_n) buf[i++] = 'n';
    if (bmodes & MODE_t) buf[i++] = 't';
    if (bmodes & MODE_s) buf[i++] = 's';
    if (bmodes & MODE_i) buf[i++] = 'i';
    if (bmodes & MODE_m) buf[i++] = 'm';
    return buf[0..i].idup;
  }

  static bool validateName(string s) {
    /* RFC 2812 Section 1.3 -- fuck that rubbish */
    if (s.length < 2 || s.length > 50)
      return false;
    if (s[0] != '#')
      return false;
    foreach (c; s[1..$])
      if (!c.isalpha && !c.isdigit)
        return false;
    return true;
  }
}

/* Representation of user-channel relationship */
class UserChannel {
  User user;
  Channel chan;
  bool channelOperator;
  bool channelHalfOperator;
  bool channelVoice;
  this(User user, Channel chan) {
    this.user = user;
    this.chan = chan;
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

/* Transmit server [numeric] message to specified user -- this function expects that
 * the first format in 'fmt' is an %s to be substituted with the receiving user's
 * nick.
 */
void txsn(string fmt, T...)(User user, T a) {
  user.send(format(serverMessagePrefix ~ fmt ~ "\r\n", user.nick, a));
}
/* Retransmit user message to specified user */
void txum(string fmt, T...)(User user, T a) {
  user.send(format(":%s!%s@%s " ~ fmt ~ "\r\n", user.nick, user.username, user.hostname, a));
}
/* RPL_WHOREPLY */
void tx352(User user, UserChannel uc) {
  user.txsn!"352 %s %s ~%s %s %s %s H%sx :0 %s"(
    uc.chan.name
  , uc.user.username
  , uc.user.hostname
  , serverHostname
  , uc.user.nick
  , uc.channelOperator ? "@" : uc.channelVoice ? "+" : ""
  , uc.user.realname
  );
}
/* ERR_NOSUCHCHANNEL */
void tx403(User user, string channame) {
  user.txsn!"403 %s %s :No such channel"(channame);
}

shared {
  logircd.Channel[string] channels;
  User[string] usersByNick;
  User[uint] usersByIid;
}

shared static this() {
  serverHostname = to!string(core.stdc.stdlib.getenv("HOSTNAME"));
  serverMessagePrefix = ":" ~ serverHostname ~ " ";

  int iidCounter = 0;
  int sentMessageCounter;
  string srvCmdFmt = ":logircd %s %s :%s\r\n";

  listenTCP(6667, (conn) {
    logInfo("New client!");
    string quitReason = "No reason given.";
    auto user = new User(conn, iidCounter);
    usersByIid[iidCounter] = user;
    iidCounter++;
    bool quit = false;

    void sendMessage(string cmd, string msg) {
      user.send(format(srvCmdFmt, cmd, user.nick, msg));
    }

    void txsn(string fmt, T...)(T a) { user.txsn!fmt(a); }
    void txum(string fmt, T...)(T a) { user.txum!fmt(a); }

    user.rtask = runTask({
      import std.stdio;
      while (!quit && conn.connected) { try {
        auto line = cast(string) conn.readLine(4096, "\r\n");
        if (line.length == 0)
          continue;
        logInfo(format("(server) <- (%s)\t %s", user.nick, line));
        string[] words;
        words.reserve(16);
        string lineParser = line;
        while (lineParser.length) {
          auto n = lineParser.indexOf(' ');
          auto m = lineParser.indexOf(':');
          if (n < 0) {
            words ~= lineParser[0..$];
            lineParser.length = 0;
            break;
          }
          words ~= lineParser[0..n];
          if (m == n+1) {
            words ~= lineParser[m+1..$];
            lineParser.length = 0;
            break;
          }
          lineParser = lineParser[n+1..$];
        }
        writeln("command parsed: \"", std.array.join(words, "\", \""), '"');
        switch (words[0]) {
          case "CAP":
            if (words.length == 2 && words[1] == "LS")
              txsn!"CAP %s LS :account-notify away-notify userhost-in-names";
            // TODO REQ -> ACK
            break;
          case "NICK":
            if (words.length < 2)
            {
              txsn!"431 %s :No nick given.";
            }
            else if (words[1] in usersByNick)
            {
              txsn!"433 %s :Nick already in use."(words[1]);
            }
            else if (!User.validateNick(words[1])) {
              txsn!"432 %s %s :Erroneous nickname."(words[1]);
            }
            else
            {
              if (user.nick in usersByNick)
                usersByNick.remove(user.nick);
              usersByNick[words[1]] = user;
              // XXXASDF
              auto msg = format(":%s!%s@%s NICK %s\r\n", user.nick, user.username, user.hostname, words[1]);
              sentMessageCounter++;
              user.lastSentMessageId = sentMessageCounter;
              foreach (chan; user.channels)
              {
                foreach (cuser; chan.chan.users)
                {
                  if (cuser.user.lastSentMessageId != sentMessageCounter)
                  {
                    cuser.user.lastSentMessageId = sentMessageCounter;
                    cuser.user.send(msg);
                  }
                }
              }
              user.nick = words[1];
              //sendMessage("NOTICE", format("*** You are now known as %s", user.nick));
            }
            break;
          case "USER":
            /* TODO parse this correctly (look for the colon) */
            if (words.length < 5)
            {
              logInfo("    malformed USER command TODO handle this");
            }
            else
            {
              user.username   = words[1];
              user.hostname   = words[2];
              user.servername = words[3];
              /* TODO check for colon? */
              user.realname   = words[4];
              user.loggedin   = true;
              txsn!"001 %s :Welcome to LogIRCd, %s!%s@%s"(user.nick, user.username, user.hostname);
              txsn!"002 %s :Your host is %s, running %s"(serverHostname, softwareFullname);
              txsn!"003 %s :This server was created Sat Jul 5 2014 at 23:39:00 EDT";
              txsn!"004 %s %s %s a aioOw abehiIklmnostv"(serverHostname, softwareFullname);
              txsn!"251 %s :There are %d users and 0 invisible on 1 servers"(usersByNick.length);
              txsn!"252 %s 0 :operator(s) online";
              txsn!"372 %s :This is the message of the day!";
              txum!"MODE %s +x"(user.nick);
              // TODO
            }
            break;
          case "TOPIC":
            if (words.length == 2) {
              /* Retrieve topic */
              if (words[1] in channels) {
                auto channel = channels[words[1]];
                if (channel.topic) {
                  /* 332 RPL_TOPIC */
                  txsn!"332 %s %s :%s"(channel.name, channel.topic);
                  /* 333 RPL_TOPICWHOTIME */
                  txsn!"333 %s %s %s"(channel.name, channel.topicWhoTime);
                } else {
                  /* 331 RPL_NOTOPIC */
                  txsn!"331 %s %s :No topic set"(words[1]);
                }
              }
              else txsn!"403 %s %s :No such channel"(words[1]);
            } else if (words.length > 2) {
              /* Set topic */
              if (words[1] in channels) {
                channels[words[1]].setTopic(user, words[2]);
              }
              else txsn!"403 %s %s :No such channel"(words[1]);
            }
            else sendMessage("NOTICE", "Sorry, logircd did not understand your TOPIC command");
            break;

          case "MODE":
            if (words.length >= 2)
            {
              auto target = words[1];
              /* Target is a channel? */
              if (target[0] == '#')
              {
                /* ERR_NOSUCHCHANNEL */
                if (target !in user.channels)
                {
                  user.tx403(target);
                  break;
                }

                auto chan = channels[target];

                /* RPL_CHANNELMODEIS */
                if (words.length == 2)
                {
                  txsn!"423 %s %s %s"(target, chan.modeString); 
                  break;
                }

                auto mode = words[2];

                if (words.length == 3)
                {
                  bool modeOn;
                  if (mode[0] == '+')
                    modeOn = true;
                  else if (mode[0] == '-')
                    modeOn = false;
                  else
                  {
                    sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
                    break;
                  }

                  switch (mode)
                  {
                    /* RPL_BANLIST */
                    case "+b":
                      foreach (ban; chan.bans)
                        txsn!"367 %s %s %s"(target, ban);
                      break;
                    case "+n":
                    case "-n":
                      user.channels[target].chan.setBooleanMode(user, Channel.MODE_n, modeOn);
                      break;
                    case "+t":
                    case "-t":
                      user.channels[target].chan.setBooleanMode(user, Channel.MODE_t, modeOn);
                      break;
                    case "+s":
                    case "-s":
                      user.channels[target].chan.setBooleanMode(user, Channel.MODE_s, modeOn);
                      break;
                    case "+m":
                    case "-m":
                      user.channels[target].chan.setBooleanMode(user, Channel.MODE_m, modeOn);
                      break;
                    case "+i":
                    case "-i":
                      user.channels[target].chan.setBooleanMode(user, Channel.MODE_i, modeOn);
                      break;
                    default:
                      sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
                      break;
                  }
                  break;
                }

                if (words.length >= 3)
                {
                  auto mode = words[2];
                  switch (mode)
                  {
                    case "+o":
                    case "-o":
                      if (words[3] in usersByNick) {
                        auto ouiid = usersByNick[words[3]].iid;
                        if (ouiid in uc.chan.users) {
                          auto giveOps = words[2][0] == '+';
                          uc.chan.users[ouiid].channelOperator = giveOps;
                          foreach (u2; uc.chan.users.values)
                            tx352(u2.user, uc);
                        }
                      }
                      break;
                      }
                }
              }
            }
            
            if (words[1] in user.channels) {
              auto uc = user.channels[words[1]];
              /* Channel Mode message, section 3.2.3 RFC2812 */
              if (words.length == 4)
              switch (words[2]) {
                case "+o":
                case "-o":
                  if (words[3] in usersByNick) {
                    auto ouiid = usersByNick[words[3]].iid;
                    if (ouiid in uc.chan.users) {
                      auto giveOps = words[2][0] == '+';
                      uc.chan.users[ouiid].channelOperator = giveOps;
                      foreach (u2; uc.chan.users.values)
                        tx352(u2.user, uc);
                    }
                  }
                  break;
                default:
                  sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
              }
              else if (words.length == 2) {
                auto target = words[1];

                if (target[0] == '#') {
                }
                else
                  sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
              }
              else
                sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
            }
            else
              sendMessage("NOTICE", "Sorry, that invocation of MODE has not been implemented.");
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
              if (!Channel.validateName(words[1])) {
                txsn!"403 %s %s :No such channel"(words[1]);
                break;
              }
              bool giveOps = false;
              if (words[1] !in channels) {
                channels[words[1]] = new logircd.Channel(words[1]);
                giveOps = true;
              }
              /* Broadcast JOIN message */
              auto channel = channels[words[1]];
              auto msg = format(":%s!%s@%s JOIN %s *\r\n", user.nick, user.username, user.hostname, channel.name);
              auto uc = channel.join(user);
              if (giveOps)
                uc.channelOperator = true;
              foreach (cuser; channel.users)
                cuser.user.send(msg);
              if (channel.topic) {
                /* 332 RPL_TOPIC */
                txsn!"332 %s %s :%s"(channel.name, channel.topic);
                /* 333 RPL_TOPICWHOTIME */
                txsn!"333 %s %s %s"(channel.name, channel.topicWhoTime);
              } else {
                /* 331 RPL_NOTOPIC */
                txsn!"331 %s %s :No topic set"(words[1]);
              }
              txsn!"353 %s @ %s :%s"(channel.name, channel.names);
              txsn!"366 %s %s :End of /NAMES list."(channel.name);
              /* WHO response
              txsn!"315 %s %s :End of /WHO list."(channel.name);
              */
            }
            break;
          case "PRIVMSG":
            if (words.length < 3)
            { /* TODO */ }
            else {
              if (words[1] in usersByNick)
                // TODO use txum()
                usersByNick[words[1]].send(format(":%s!%s@%s PRIVMSG %s :%s\r\n",
                  user.nick, user.username, user.hostname, words[1], words[2]));
              else if (words[1] in channels)
                foreach (cuser; channels[words[1]].users)
                  if (cuser.user !is user)
                    // XXX ASDF
                    cuser.user.txum!"PRIVMSG %s :%s"(words[1], words[2]);
            }
            break;
          case "PING":
            /* Only implementing PING from client. xchat2 doesn't send PING spuriously, it seems,
             * but irssi does, and disconnects after 301 seconds on my system. Also, we assume that
             * we are the one being pinged! XXX */
            if (words.length == 2) {
              /* This is how AfterNET responded... XXX TODO */
              txsn!":%s PONG %s :%s"(words[1], words[1], words[1]);
            }
            break;
          case "QUIT":
            quitReason = words.length > 1 ? words[1] : "No reason given.";
            quit = true;
            break;
          case "LIST":
            /* RPL_LISTSTART */
            /* lol what does this message even mean? silly afternet */
            txsn!"321 %s Channel :Users  Name";
            auto channelNames = words.length == 1 ? channels.keys : words[1].split(',');
            foreach (cname; channelNames) {
              if (cname in channels) {
                auto chan = channels[cname];
                /* RPL_LIST */
                txsn!"322 %s %s %d :%s"(chan.name, chan.users.length, chan.topic);
              }
            }
            /* RPL_LISTEND */
            txsn!"323 %s :End of /LIST";
            break;
          /*case "WHO":
            bool whoOps = words[$-1] == "o";
            if (words.length == 1)
            {
              foreach (ch; channels) {
                foreach (uc; ch.users) {
                  tx352(user, uc
                  txsn!"352 %s %s %s %s %s %s H%sx :0 %s"
                  , serverHostname
                  , user.nick
                  , ch.name
                  , uc.user.username
                  , uc.user.hostname
                  , serverHostname // TODO?
                  , uc.user.nick
                  , uc.channelOperator ? "@":""
                  , uc.user.realname
                  ));
                }
              }
              break;
            }
            auto masks = words[1.. whoOps ? $-1 : $];
            foreach (mask; masks) {
              if (mask[0] == '#') { 
                // channel WHO query
                if (mask in channels) {
                  auto ch = channels[mask];
                  foreach (uc; ch.users) {
                    txsn!"352 %s %s %s %s %s %s H%sx :0 %s"
                    , serverHostname
                    , user.nick
                    , ch.name
                    , uc.user.username
                    , uc.user.hostname
                    , serverHostname // TODO?
                    , uc.user.nick
                    , uc.channelOperator ? "@":""
                    , uc.user.realname
                    ));
                  }
                } else if (mask in usersByNick) {
                  foreach (ch; channels) {
                    foreach (uc; ch.users) {
                      if (uc.user.nick == mask)
                      txsn!"352 %s %s %s %s %s %s H%sx :0 %s"
                      , serverHostname
                      , user.nick
                      , ch.name
                      , uc.user.username
                      , uc.user.hostname
                      , serverHostname // TODO?
                      , uc.user.nick
                    , uc.channelOperator ? "@":""
                      , uc.user.realname
                      ));
                    }
                  }
                }
              }
            }
            break;*/
          default:
            sendMessage("NOTICE", format("*** Unknown command: %s", words[0]));
            break;
        }
      } catch (Throwable o) {
        logInfo(format("Uncaught exception for %s!%s@%s in rtask: %s",
          user.nick, user.username, user.hostname, o));
        quit = true;
        quitReason = "Error reading from socket.";
      }
    }});

    user.wtask = runTask({
      while (!quit && conn.connected) { try {
        receive((string s) {
          conn.write(s);
        });
      } catch (Throwable o) {
        logInfo(format("Uncaught exception for %s!%s@%s in wtask: %s",
          user.nick, user.username, user.hostname, o));
        quit = true;
        quitReason = "Error writing to socket.";
      }
    }});

    sendMessage("NOTICE", "*** Welcome to the server!");

    scope(exit)
    {
      foreach (ou; usersByIid.values)
        if (ou !is user)
          ou.send(format(":%s!%s@%s QUIT :%s", user.nick, user.username, user.hostname, quitReason));
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
