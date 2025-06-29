package com.example.nvs.model;

public class CVEEntry {
    private final String id;
    private final String summary;
    private final double cvssScore;
    private final String publishedDate;

    public CVEEntry(String id, String summary, double cvssScore, String publishedDate) {
        this.id = id;
        this.summary = summary;
        this.cvssScore = cvssScore;
        this.publishedDate = publishedDate;
    }

    public String getId() {
        return id;
    }

    public String getSummary() {
        return summary;
    }

    public double getCvssScore() {
        return cvssScore;
    }

    public String getPublishedDate() {
        return publishedDate;
    }
}
