package org.springframework.security.acls.mongodb;

import com.mongodb.Mongo;
import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodProcess;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import java.io.IOException;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

public class MongoDBTestExecutionListener extends AbstractTestExecutionListener {

    private MongodExecutable mongodExe;
    private MongodProcess mongod;
    private Mongo mongo;

    @Override
    public void beforeTestClass(TestContext testContext) throws IOException {
        MongodStarter starter = MongodStarter.getDefaultInstance();

        String bindIp = "localhost";
        int port = 27017;
        IMongodConfig mongodConfig = new MongodConfigBuilder()
                .version(Version.Main.PRODUCTION)
                .net(new Net(bindIp, port, Network.localhostIsIPv6()))
                .build();

        mongodExe = starter.prepare(mongodConfig);
        mongod = mongodExe.start();
    }

//    @Override
//    public void prepareTestInstance(TestContext testContext) {
//        if (mongod != null) {
//
//        }
//    }

    @Override
    public void afterTestClass(TestContext testContext) {
        if (mongodExe != null) {
            mongodExe.stop();
        }
    }
}
