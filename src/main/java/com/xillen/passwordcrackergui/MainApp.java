package com.xillen.passwordcrackergui;

import com.xillen.passwordcrackergui.controllers.MainController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

public class MainApp extends Application {
    @Override
    public void start(Stage stage) throws Exception {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/main.fxml"));
        Parent root = loader.load();

        Scene scene = new Scene(root, 1100, 720);
        scene.getStylesheets().add(getClass().getResource("/styles/dark.css").toExternalForm());

        stage.setTitle("XillenBloodhound — t.me/XillenAdapter • github.com/BengaminButton");
        try {
            var iconStream = getClass().getResourceAsStream("/icons/lock.png");
            if (iconStream != null) {
                stage.getIcons().add(new Image(iconStream));
            }
        } catch (Throwable ignored) {
            // If icon not found, continue without it
        }
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
