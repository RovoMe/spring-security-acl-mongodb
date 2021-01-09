package org.springframework.security.acls.mongodb;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;
import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.MongodConfig;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import org.bson.Document;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.acls.dao.AclRepository;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;

import java.io.IOException;
import java.util.Date;

@SpringBootTest
@ContextConfiguration(classes = {TestContextConfiguration.class})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
abstract class SetupTestMongoDBAcl {

    private static MongodExecutable mongodExecutable;

    @Autowired
    protected AclRepository aclRepository;

    @BeforeAll
    static void setUp(@Autowired MongoClient mongo,
            @Autowired String database,
            @Autowired int port,
            @Autowired String collection) throws IOException {
        // Setup MongoDB
        MongodStarter starter = MongodStarter.getDefaultInstance();
        MongodConfig mongodConfig = MongodConfig.builder()
                .version(Version.Main.PRODUCTION)
                .net(new Net(port, Network.localhostIsIPv6()))
                .build();

        mongodExecutable = starter.prepare(mongodConfig);
        mongodExecutable.start();

        MongoDatabase db = mongo.getDatabase(database);
        db.createCollection(collection);
        db.getCollection(collection).insertOne(new Document("testObject", new Date()));
    }

    @AfterAll
    static void tearDownAll() {
        if (mongodExecutable != null) {
            mongodExecutable.stop();
        }
    }
}
