/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.mongodb;

import de.flapdoodle.embed.mongo.MongodExecutable;
import de.flapdoodle.embed.mongo.MongodStarter;
import de.flapdoodle.embed.mongo.config.IMongodConfig;
import de.flapdoodle.embed.mongo.config.MongodConfigBuilder;
import de.flapdoodle.embed.mongo.config.Net;
import de.flapdoodle.embed.mongo.distribution.Version;
import de.flapdoodle.embed.process.runtime.Network;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

import java.io.IOException;

/**
 * Spring test execution listener which starts an embedded MongoDB on the default <i>27017</i> port and shuts the
 * DB server down after the class has finished with the tests.
 *
 * @author Roman Vottner
 * @since 4.3
 */
public class MongoDBTestExecutionListener extends AbstractTestExecutionListener {

	private MongodExecutable mongodExe;

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
		mongodExe.start();
	}

	@Override
	public void afterTestClass(TestContext testContext) {
		if (mongodExe != null) {
			mongodExe.stop();
		}
	}
}
