module com.example.nvs {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.web;

    requires org.controlsfx.controls;
    requires org.kordamp.ikonli.javafx;
    requires org.kordamp.bootstrapfx.core;
    requires eu.hansolo.tilesfx;
    requires com.google.gson;
    requires okhttp3;
    requires itextpdf;

    opens com.example.nvs to javafx.fxml;
    exports com.example.nvs;
    exports com.example.nvs.ui;
    opens com.example.nvs.ui to javafx.fxml;
    opens com.example.nvs.model to javafx.base;

}