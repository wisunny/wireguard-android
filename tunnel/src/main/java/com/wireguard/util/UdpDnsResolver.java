package com.wireguard.util;


import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import android.util.Log;

public class UdpDnsResolver {
    private final static String TAG = "WireGuard/Util/UdpDnsResolver";
    private static volatile InetAddress dnsServer;

    private UdpDnsResolver() {} // 防止实例化

    public static void setDnsServer(InetAddress server) {
        dnsServer = server;
    }

    public static InetAddress getDnsServer() {
        return dnsServer;
    }    


    public static List<InetAddress> resolve(String domain, int timeoutSec, int retries, int port) throws Exception {
        List<InetAddress> results = new ArrayList<>();
        int[] qtypes = {1, 28}; // A + AAAA
        InetAddress dns = getDnsServer() != null ? getDnsServer() : InetAddress.getByName("223.5.5.5");
        Log.i(TAG, "custom dns server:" + dns.getHostAddress() + " port:" + port);
        for (int qtype : qtypes) {
            byte[] query = buildDnsQuery(domain, qtype);
            for (int i = 0; i < retries; i++) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.setSoTimeout(timeoutSec * 1000);
                    DatagramPacket request = new DatagramPacket(query, query.length, dns, port);
                    socket.send(request);

                    byte[] buf = new byte[512];
                    DatagramPacket response = new DatagramPacket(buf, buf.length);
                    socket.receive(response);

                    results.addAll(parseDnsResponse(response.getData(), qtype));
                    break; // 成功就不重试
                } catch (Exception e) {
                    if (i == retries - 1) throw e;
                }
            }
        }
        return results;
    }

    private static byte[] buildDnsQuery(String domain, int qtype) {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.putShort((short) new Random().nextInt(0xFFFF)); // ID
        buffer.putShort((short) 0x0100); // 标准查询
        buffer.putShort((short) 1);      // Questions
        buffer.putShort((short) 0);      // Answer RRs
        buffer.putShort((short) 0);      // Authority RRs
        buffer.putShort((short) 0);      // Additional RRs

        for (String label : domain.split("\\.")) {
            buffer.put((byte) label.length());
            buffer.put(label.getBytes());
        }
        buffer.put((byte) 0x00);
        buffer.putShort((short) qtype);
        buffer.putShort((short) 1); // IN

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        return data;
    }

    private static List<InetAddress> parseDnsResponse(byte[] data, int qtype) throws Exception {
        List<InetAddress> ips = new ArrayList<>();
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.position(12);

        // 跳过查询
        while (buffer.get() != 0) {} // QNAME
        buffer.getShort(); // QTYPE
        buffer.getShort(); // QCLASS

        while (buffer.remaining() > 12) {
            buffer.getShort(); // name
            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort(); // class
            buffer.getInt();   // ttl
            int rdLength = buffer.getShort() & 0xFFFF;

            if (type == qtype) {
                byte[] addr = new byte[rdLength];
                buffer.get(addr);
                ips.add(InetAddress.getByAddress(addr));
            } else {
                buffer.position(buffer.position() + rdLength);
            }
        }
        return ips;
    }
}
