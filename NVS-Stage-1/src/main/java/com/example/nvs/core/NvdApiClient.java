package com.example.nvs.core;

import com.example.nvs.model.CVEEntry;
import com.google.gson.*;
import okhttp3.*;

import java.io.IOException;
import java.util.*;

public class NvdApiClient {
    private static final String BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final String API_KEY = "00ccbb80-4d82-4ed5-af30-8cf2f0f72532";  // <-- make sure it's trimmed
    private static final OkHttpClient client = new OkHttpClient();

    public static List<CVEEntry> fetchByCpe(String cpeName) {
        List<CVEEntry> list = new ArrayList<>();

        HttpUrl url = HttpUrl.parse(BASE).newBuilder()
                .addQueryParameter("cpeName", cpeName)
                .addQueryParameter("resultsPerPage", "10")
                .build();

        System.out.println("📡 Requesting URL: " + url);

        Request.Builder reqB = new Request.Builder().url(url);
        if (!API_KEY.isBlank()) {
            reqB.header("X-Api-Key", API_KEY.trim());
        }

        try (Response resp = client.newCall(reqB.build()).execute()) {
            if (!resp.isSuccessful() || resp.body() == null) {
                System.err.println("❌ NVD API failed: " + resp.code());
                return list;
            }

            String body = resp.body().string();
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            JsonArray vulns = root.getAsJsonArray("vulnerabilities");

            if (vulns == null || vulns.isEmpty()) {
                System.out.println("ℹ️ No CVEs found for CPE: " + cpeName);
                return list;
            }

            for (JsonElement e : vulns) {
                JsonObject item = e.getAsJsonObject().getAsJsonObject("cve");

                String id = item.get("id").getAsString();
                String published = item.get("published").getAsString();

                String desc = item.getAsJsonArray("descriptions")
                        .get(0).getAsJsonObject().get("value").getAsString();

                double score = 0.0;
                JsonObject metrics = item.getAsJsonObject("metrics");

                if (metrics.has("cvssMetricV31")) {
                    JsonObject cvss = metrics.getAsJsonArray("cvssMetricV31")
                            .get(0).getAsJsonObject()
                            .getAsJsonObject("cvssData");
                    score = cvss.get("baseScore").getAsDouble();
                } else if (metrics.has("cvssMetricV2")) {
                    JsonObject cvss = metrics.getAsJsonArray("cvssMetricV2")
                            .get(0).getAsJsonObject()
                            .getAsJsonObject("cvssData");
                    score = cvss.get("baseScore").getAsDouble();
                }

                list.add(new CVEEntry(id, desc, score, published));
            }

        } catch (IOException ex) {
            System.err.println("⚠️ Exception calling NVD API: " + ex.getMessage());
        }

        return list;
    }
}
