package com.example.nvs.model;

import java.util.List;

public class ScanResultModel {
    private final String ipAddress;
    private final List<Integer> openPorts;

    public ScanResultModel(String ipAddress, List<Integer> openPorts) {
        this.ipAddress = ipAddress;
        this.openPorts = openPorts;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public int getOpenPortCount() {
        return openPorts.size();
    }

    public String getOpenPorts() {
        return openPorts.toString();
    }
}
