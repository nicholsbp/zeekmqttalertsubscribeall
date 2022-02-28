module Mqtt;

export {
	redef enum Notice::Type += { Mqtt::Subscribe };
	redef enum Log::ID += { LOG };
}

function get_message_length (msg: string): count {
	local length = ((bytestring_to_count(hexstr_to_bytestring(sub_bytes(msg, 3, 2))) + 2) *2);
	return length;
}

function alert_subscribe_all (msg: string, c: connection): bool {
	if (sub_bytes(msg, 1, 2) == "82") {
		local topic = hexstr_to_bytestring(sub_bytes(msg, 13, get_message_length(msg) - 14));
		if ("#" in topic) {
			NOTICE([ $note = Mqtt::Subscribe, $msg = fmt("%s attempts to subscribe to %s topics", c$id$orig_h, topic)]);
		}
	}
	return F;
}

event packet_contents(c: connection, contents: string) {
        if (c$id$resp_p == 1883/tcp) {
				local messageRaw = string_to_ascii_hex(contents);
                local messageLength: count;
                local message: string;
                
                while (messageRaw != "") {
                        messageLength = get_message_length(messageRaw);
                        message = sub_bytes(messageRaw, 1, messageLength);
                        messageRaw = subst_string(messageRaw, message, "");
                        alert_subscribe_all(message, c);
                }
        }
}
