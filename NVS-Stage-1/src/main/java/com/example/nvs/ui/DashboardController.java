package com.example.nvs.ui;

import com.example.nvs.core.PortScanner;
import com.example.nvs.core.NvdApiClient;
import com.example.nvs.model.CVEEntry;
import com.example.nvs.model.ScanResultModel;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.PieChart;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.FileChooser;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.stream.Stream;

public class DashboardController {

    @FXML
    private TableView<ScanResultModel> scanTable;
    @FXML
    private TableColumn<ScanResultModel, String> ipColumn;
    @FXML
    private TableColumn<ScanResultModel, Integer> portCountColumn;
    @FXML
    private TableColumn<ScanResultModel, String> portsColumn;

    @FXML
    private PieChart portPieChart;

    @FXML
    private TableView<CVEEntry> vulnTable;
    @FXML
    private TableColumn<CVEEntry, String> cveIdCol;
    @FXML
    private TableColumn<CVEEntry, Double> cvssCol;
    @FXML
    private TableColumn<CVEEntry, String> summaryCol;
    @FXML
    private TableColumn<CVEEntry, String> pubDateCol;

    private ObservableList<ScanResultModel> scanData = FXCollections.observableArrayList();
    private ObservableList<CVEEntry> vulnData = FXCollections.observableArrayList();

    @FXML
    private void initialize() {
        ipColumn.setCellValueFactory(new PropertyValueFactory<>("ipAddress"));
        portCountColumn.setCellValueFactory(new PropertyValueFactory<>("openPortCount"));
        portsColumn.setCellValueFactory(new PropertyValueFactory<>("openPorts"));
        scanTable.setItems(scanData);

        cveIdCol.setCellValueFactory(new PropertyValueFactory<>("id"));
        cvssCol.setCellValueFactory(new PropertyValueFactory<>("cvssScore"));
        summaryCol.setCellValueFactory(new PropertyValueFactory<>("summary"));
        pubDateCol.setCellValueFactory(new PropertyValueFactory<>("publishedDate"));
        vulnTable.setItems(vulnData);
    }

    @FXML
    private void handleExportReport() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save Report");
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("PDF File", "*.pdf"),
                new FileChooser.ExtensionFilter("CSV File", "*.csv")
        );
        File file = chooser.showSaveDialog(null);
        if (file != null) {
            if (file.getName().endsWith(".pdf")) {
                exportToPDF(file);
            } else if (file.getName().endsWith(".csv")) {
                exportToCSV(file);
            }
        }
    }

    private void exportToCSV(File file) {
        try (FileWriter writer = new FileWriter(file)) {
            writer.append("CVE ID,CVSS,Summary,Published Date\n");
            for (CVEEntry entry : vulnData) {
                writer.append(String.format("%s,%.1f,%s,%s\n",
                        entry.getId(),
                        entry.getCvssScore(),
                        entry.getSummary().replace(",", " "),
                        entry.getPublishedDate()));
            }
        } catch (IOException e) {
            System.err.println("Error writing CSV: " + e.getMessage());
        }
    }

    private void exportToPDF(File file) {
        Document document = new Document();
        try {
            PdfWriter.getInstance(document, new FileOutputStream(file));
            document.open();

            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18);
            Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 12);

            document.add(new Paragraph("Network Vulnerability Report", titleFont));
            document.add(new Paragraph("Generated: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), normalFont));
            document.add(Chunk.NEWLINE);

            if (vulnData.isEmpty()) {
                document.add(new Paragraph("No vulnerabilities detected.", normalFont));
            } else {
                PdfPTable table = new PdfPTable(4);
                table.setWidthPercentage(100);
                table.setWidths(new float[]{2, 1, 5, 2});

                Stream.of("CVE ID", "CVSS", "Summary", "Published Date").forEach(header -> {
                    PdfPCell cell = new PdfPCell(new Phrase(header, FontFactory.getFont(FontFactory.HELVETICA_BOLD)));
                    cell.setBackgroundColor(BaseColor.LIGHT_GRAY);
                    table.addCell(cell);
                });

                for (CVEEntry entry : vulnData) {
                    table.addCell(new Phrase(entry.getId(), normalFont));
                    table.addCell(new Phrase(String.valueOf(entry.getCvssScore()), normalFont));
                    table.addCell(new Phrase(entry.getSummary(), normalFont));
                    table.addCell(new Phrase(entry.getPublishedDate(), normalFont));
                }

                document.add(table);
            }

        } catch (Exception e) {
            System.err.println("Error exporting to PDF: " + e.getMessage());
        } finally {
            document.close();
        }
    }

    @FXML
    private void handleScanClick() {
        scanData.clear();
        vulnData.clear();
        portPieChart.getData().clear();

        Task<Void> scanTask = new Task<>() {
            @Override
            protected Void call() {
                Map<Integer, Integer> portFrequency = new HashMap<>();
                Map<Integer, String> portCpe = Map.ofEntries(
                        Map.entry(22, "cpe:2.3:a:openbsd:openssh:9.3p2:*:*:*:*:*:*"),
                        Map.entry(445, "cpe:2.3:a:samba:samba:4.17.0:*:*:*:*:*:*"),
                        Map.entry(80, "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*")
                );

                String ip = PortScanner.getLocalIPAddress();
                List<Integer> openPorts = PortScanner.scanOpenPorts(ip, 20, 1024, (current, total) -> {
                    System.out.println("Scanning port " + current + "/" + total + " on " + ip);
                });

                Platform.runLater(() -> scanData.add(new ScanResultModel(ip, openPorts)));

                for (int port : openPorts) {
                    portFrequency.put(port, portFrequency.getOrDefault(port, 0) + 1);
                    if (portCpe.containsKey(port)) {
                        List<CVEEntry> cves = NvdApiClient.fetchByCpe(portCpe.get(port));
                        Platform.runLater(() -> vulnData.addAll(cves));
                    }
                }

                Platform.runLater(() -> {
                    portPieChart.getData().clear();
                    for (Map.Entry<Integer, Integer> entry : portFrequency.entrySet()) {
                        portPieChart.getData().add(new PieChart.Data("Port " + entry.getKey(), entry.getValue()));
                    }
                });

                return null;
            }
        };

        new Thread(scanTask).start();
    }
}
