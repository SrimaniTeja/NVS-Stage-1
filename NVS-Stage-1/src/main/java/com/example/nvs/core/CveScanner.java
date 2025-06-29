package com.example.nvs.core;

import com.example.nvs.model.CVEEntry;
import com.example.nvs.core.NvdApiClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CveScanner {

    // Common port to CPE mapping (expand this based on services you expect)
    private static final Map<Integer, String> portToCpe = Map.of(
            80, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*",
            22, "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*",
            443, "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*",
            3306, "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*",
            21, "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*"
    );

    /**
     * Scans for CVEs based on open ports by mapping them to known CPEs.
     *
     * @param openPorts List of open ports detected during scanning.
     * @return List of CVE entries relevant to the services running on those ports.
     */
    public static List<CVEEntry> scanForCVEs(List<Integer> openPorts) {
        List<CVEEntry> results = new ArrayList<>();

        for (int port : openPorts) {
            if (portToCpe.containsKey(port)) {
                String cpe = portToCpe.get(port);
                List<CVEEntry> cveList = NvdApiClient.fetchByCpe(cpe);
                results.addAll(cveList);
            }
        }

        return results;
    }

    /**
     * Optionally expose method to allow custom CPE scanning
     */
    public static List<CVEEntry> scanByCustomCpe(String cpe) {
        return NvdApiClient.fetchByCpe(cpe);
    }
}
