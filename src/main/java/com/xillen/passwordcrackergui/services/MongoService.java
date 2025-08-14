package com.xillen.passwordcrackergui.services;

import org.bson.Document;
import com.mongodb.client.*;

public class MongoService {
    private final MongoClient client;
    private final MongoDatabase db;
    private final MongoCollection<Document> results;

    public MongoService() {
        // Default local MongoDB; adjust via env MONGO_URI if needed
        String uri = System.getenv().getOrDefault("MONGO_URI", "mongodb://localhost:27017");
        client = MongoClients.create(uri);
        db = client.getDatabase("password_cracker");
        results = db.getCollection("results");
    }

    public void saveResult(String type, String target, String method, boolean success, String password) {
        Document d = new Document()
                .append("type", type)
                .append("target", target)
                .append("method", method)
                .append("success", success)
                .append("password", password)
                .append("ts", System.currentTimeMillis());
        results.insertOne(d);
    }
}
