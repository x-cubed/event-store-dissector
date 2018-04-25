local eventStore = Proto("event-store", "Event Store");

-- Mapping the command IDs to the command names used by Event Store
local commands = {
  [0x01] = "HeartbeatRequest",
  [0x02] = "HeartbeatResponse",
  
  [0x03] = "Ping",
  [0x04] = "Pong",
 
  [0x82] = "WriteEvents",
  [0x83] = "WriteEventsCompleted",
  
  [0x84] = "TransactionStart",
  [0x85] = "TransactionStartCompleted",
  [0x86] = "TransactionWrite",
  [0x87] = "TransactionWriteCompleted",
  [0x88] = "TransactionCommit",
  [0x89] = "TransactionCommitCompleted",
  
  [0x8A] = "DeleteStream",
  [0x8B] = "DeleteStreamCompleted",
  
  [0xB0] = "Read",
  [0xB1] = "ReadEventCompleted",
  [0xB2] = "ReadStreamEventsForward",
  [0xB3] = "ReadStreamEventsForwardCompleted",
  [0xB4] = "ReadStreamEventsBackward",
  [0xB5] = "ReadStreamEventsBackwardCompleted",
  [0xB6] = "ReadAllEventsForward",
  [0xB7] = "ReadAllEventsForwardCompleted",
  [0xB8] = "ReadAllEventsBackward",
  [0xB9] = "ReadAllEventsBackwardCompleted",
  
  [0xC0] = "SubscribeToStream",
  [0xC1] = "SubscriptionConfirmation",
  [0xC2] = "StreamEventAppeared",
  [0xC3] = "UnsubscribeFromStream",
  [0xC4] = "SubscriptionDropped",
  
  [0xF0] = "BadRequest",
  [0xF1] = "NotHandled",
  [0xF2] = "Authenticate",
  [0xF3] = "Authenticated",
  [0xF4] = "NotAuthenticated"
}

-- Mapping the command IDs to the ProtoBuf schema names used by Event Store
local schemas = {
  [0x82] = "WriteEvents",
  [0x83] = "WriteEventsCompleted",
  
  [0x84] = "TransactionStart",
  [0x85] = "TransactionStartCompleted",
  [0x86] = "TransactionWrite",
  [0x87] = "TransactionWriteCompleted",
  [0x88] = "TransactionCommit",
  [0x89] = "TransactionCommitCompleted",
  
  [0x8A] = "DeleteStream",
  [0x8B] = "DeleteStreamCompleted",
  
  [0xB0] = "Read",
  [0xB1] = "ReadEventCompleted",
  [0xB2] = "ReadStreamEvents",
  [0xB3] = "ReadStreamEventsCompleted",
  [0xB4] = "ReadStreamEvents",
  [0xB5] = "ReadStreamEventsCompleted",
  [0xB6] = "ReadAllEvents",
  [0xB7] = "ReadAllEventsCompleted",
  [0xB8] = "ReadAllEvents",
  [0xB9] = "ReadAllEventsCompleted",
  
  [0xC0] = "SubscribeToStream",
  [0xC1] = "SubscriptionConfirmation",
  [0xC2] = "StreamEventAppeared",
  [0xC3] = "UnsubscribeFromStream",
  [0xC4] = "SubscriptionDropped",
  
  [0xF0] = "BadRequest",
  [0xF1] = "NotHandled",
  [0xF2] = "Authenticate",
  [0xF3] = "Authenticated",
  [0xF4] = "NotAuthenticated"
}

local flags = {
  [0x00] = "None",
  [0x01] = "Auth"
}

local HEADER_LENGTH = 4 + 1 + 1 + 16 -- len, cmd, flags, correlation ID

len_F = ProtoField.uint32("event-store.len", "Length")
cmd_F = ProtoField.uint8("event-store.command", "Command", nil, commands)
flags_F = ProtoField.uint8("event-store.flags", "Flags", nil, flags)
correlationId_F = ProtoField.guid("event-store.correlation-id", "Correlation ID")
username_F = ProtoField.string("event-store.username", "User name")
password_F = ProtoField.string("event-store.password", "Password")
eventStore.fields = { len_F, cmd_F, flags_F, correlationId_F, username_F, password_F }

-- Returns the complete length of the Event Store message
function get_message_len(tvb, pinfo, tree)
  local len = tvb:range(0, 4):le_uint()
  return len + 4
end

-- Dissects a whole Event Store Message
function dissect_message(tvb, pinfo, tree)
  local len = tvb:range(0, 4):le_uint()
  local cmd = tvb(4, 1):le_uint()
  local flags = tvb(5, 1):le_uint()
  local cmdName = commands[cmd]

  pinfo.cols.protocol = "Event Store"

  -- Add the message type to the info column
  if (string.find(tostring(pinfo.cols.info), "Ack=")) then
    -- Override the TCP info with just the Event Store info
    -- FIXME: Find a better way to do this rather than checking for Ack=
    pinfo.cols.info = cmdName
  else
    -- Append to the existing Event Store info
    if cmdName then
      pinfo.cols.info:append(", " .. cmdName)
    else
      cmdName = "unknown command " .. cmd
      pinfo.cols.info:append(", command " .. cmd)
    end
  end

  -- Add the header fields to the tree
  local subtree = tree:add(eventStore, tvb(), "Event Store, " .. cmdName)
  subtree:add_le(len_F, tvb(0, 4))
  subtree:add(cmd_F, tvb(4, 1))
  subtree:add(flags_F, tvb(5, 1))
  subtree:add(correlationId_F, tvb(6, 16))

  local dataStart = HEADER_LENGTH
  if (flags == 0x01) then
    -- Message contains user credentials for authentication
    local authTree = subtree:add(eventStore, tvb(), "Authentication")

    local nameStart = HEADER_LENGTH
    local nameLen = tvb(nameStart, 1):le_uint()
    authTree:add(username_F, tvb(nameStart + 1, nameLen))

    local pswdStart = nameStart + 1 + nameLen
    local pswdLen = tvb(pswdStart, 1):le_uint()
    authTree:add(password_F, tvb(pswdStart + 1, pswdLen))

    dataStart = nameStart + 1 + nameLen + 1 + pswdLen
  end

  local dataLen = len + 4 - dataStart
  if dataLen > 0 then
    -- Message also contains a data section serialized using ProtoBuf
    local messageType = schemas[cmd]
    local schema = "EVENTSTORE.CLIENT.MESSAGES." .. string.upper(messageType)  
    local dissector = DissectorTable.get("protobuf.message"):get_dissector(schema)
    if dissector == nil then
      local dataTree = subtree:add(tvb(dataStart, dataLen), cmdName)
      dataTree:add_expert_info(PI_UNDECODED, PI_NOTE, "Unable to parse ProtoBuf message. Is the dex/protobuf_dissector plugin installed?")
    else
      return dissector:call(tvb(dataStart):tvb(), pinfo, subtree)
    end
  end
  return 0
end

-- Dissects partial Event Store messages by stitching one or more TCP packets together
function eventStore.dissector(tvb, pinfo, tree)
  dissect_tcp_pdus(tvb, tree, 4, get_message_len, dissect_message)
end

-- Register this dissector to handle TCP port 1113
local tcp_table = DissectorTable.get("tcp.port");
tcp_table:add(1113, eventStore)