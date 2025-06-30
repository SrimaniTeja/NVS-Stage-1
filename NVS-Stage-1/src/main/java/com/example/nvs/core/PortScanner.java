package com.example.nvs.core;

import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class PortScanner {

    private static final int TIMEOUT = 200;
    private static final int THREAD_POOL_SIZE = 50;

    public interface ProgressCallback {
        void onProgressUpdate(int current, int total);
    }

    public static List<Integer> scanOpenPorts(String ipAddress, int startPort, int endPort, ProgressCallback callback) {
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
        int totalPorts = endPort - startPort + 1;
        AtomicInteger scannedCount = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<?>> futures = new ArrayList<>();

        for (int port = startPort; port <= endPort; port++) {
            final int currentPort = port;
            futures.add(executor.submit(() -> {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(ipAddress, currentPort), TIMEOUT);
                    openPorts.add(currentPort);
                } catch (IOException ignored) {
                }
                int progress = scannedCount.incrementAndGet();
                callback.onProgressUpdate(progress, totalPorts);
            }));
        }

        // Wait for all tasks to complete
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        executor.shutdown();
        return openPorts;
    }

    public static boolean isHostReachable(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.isReachable(500);
        } catch (IOException e) {
            return false;
        }
    }

    public static List<String> scanSubnet(String subnetPrefix) {
        List<String> activeHosts = Collections.synchronizedList(new ArrayList<>());
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 1; i < 255; i++) {
            String ip = subnetPrefix + i;
            futures.add(executor.submit(() -> {
                if (isHostReachable(ip)) {
                    activeHosts.add(ip);
                }
            }));
        }

        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (Exception ignored) {
            }
        }

        executor.shutdown();
        return activeHosts;
    }
    public static String getLocalIPAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp() || iface.isVirtual()) continue;

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        String ip = addr.getHostAddress();
                        // Ignore link-local 169.254.x.x addresses
                        if (!ip.startsWith("169.")) {
                            return ip;
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return "127.0.0.1"; // fallback
    }


}
