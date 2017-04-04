# net.craswell.common
Java - common tools.

		<javac ...>
			<classpath refid="..."/>
			<compilerarg value="-processor" />
			<compilerarg value="net.craswell.security.annotationProcessors.ConfidentialityProcessor" />
			<compilerarg value="-s" />
			<compilerarg value="..." />
		</javac>
