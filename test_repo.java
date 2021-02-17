/*
	Start program:
		1. Run the Bootstrap process [ Start --> Run when change is detected --> Termination]
		2. Start the DirectoryWatcher [ Start ---> Termination ] <Thread #1>
		3. Start the HTTP Server [ Start ---> Termination ]	<Thread #2>
*/
public class Runner {
	public static void main(String[] args) throws Exception
	{	
		//Create a process to run the SimpleHTTPServer python program
		final Process httpServer = new WindowsTerminal().executeProcess("python -m SimpleHTTPServer");
		//Attach a shutdown hook to intercept 'CTRL+C' event 
		//and shutdown the above process
		Runtime.getRuntime().addShutdownHook(new Thread(){
			public void run()
			{
				System.out.print("Shutting down the server...");
				httpServer.destroy();
				System.out.print("Done!");
			}
		});
		//Freeze the current thread until the server is shut down
		httpServer.waitFor();
		
	}
}

------------------------------------------------

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class WindowsTerminal {
	public WindowsTerminal()
	{
		//CTOR
	}
	public Process executeProcess(String cmd) 
	{
		try
		{
			final Process process = Runtime.getRuntime().exec( cmd );
			new Thread( new Runnable(){
				public void run() {
					BufferedReader terminalOutputReader = new BufferedReader( new InputStreamReader( process.getInputStream() ) );
					String terminalOutput = null;
					try {
						while( (terminalOutput = terminalOutputReader.readLine()) != null )
						{
							System.out.println( terminalOutput );
						}	
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}).start();
			return process;
		}
		catch(IOException ioe)
		{
			ioe.printStackTrace();
			return null;
		}
	}
}
--------------------------------

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;

public class DirectoryWatcher {
	
	private Path directoryPath;
	private boolean recursive = false;
	private final WatchService watchService;
	
	public DirectoryWatcher(String directoryPath, boolean recursive) throws IOException
	{
		this.recursive = recursive;
		this.directoryPath = Paths.get("directoryPath");
		
		this.watchService = FileSystems.getDefault().newWatchService();
		
		this.registerDirectory(this.directoryPath, this.recursive);
		
	}
	private void registerDirectory(final Path dir, boolean recursive) throws IOException
	{
		if( recursive )
			registerAll( dir );
		else
			register( dir );
	}
	private void register(Path dir) throws IOException
	{
		WatchKey key = dir.register( this.watchService, StandardWatchEventKinds.ENTRY_CREATE,
														StandardWatchEventKinds.ENTRY_DELETE,
														StandardWatchEventKinds.ENTRY_MODIFY );
		
	}
	private void registerAll( final Path startDir ) throws IOException
	{
		Files.walkFileTree( startDir, new SimpleFileVisitor<Path>(){
			@Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                throws IOException
            {
                register(dir);
                return FileVisitResult.CONTINUE;
            }
		});
	}
}


package com.generic;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth2.bearersignature.BearerSignature;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;

import java.util.Optional;

/**
 *  A generic OAuth 2.0 API for interfacing with Scribe. Usage as follows:
 *  
 *  final GenericOAuth2API handler = GenericOAuth2API.Builder
 *                 .aGenericOAuth2API()
 *                 .withRefreshTokenEndpoint("https://oauth2.googleapis.com/token")
 *                 .build();
 *  final OAuth20Service service = new ServiceBuilder("API_KEY")
 *                 .apiSecret("API_SECRET")
 *                 .build(handler);
 *  OAuth2AccessToken token = service.refreshAccessToken("REFRESH_TOKEN");
 *  System.out.println(token.getAccessToken());
 * */
public class GenericOAuth2API extends DefaultApi20 {

    private String accessTokenEndpoint;
    private String refreshTokenEndpoint;
    private String revokeTokenEndpoint;
    private String authorizationBaseUrl;
    private TokenExtractor<OAuth2AccessToken> tokenExtractor;
    private BearerSignature bearerSignature;
    private Verb accessTokenVerb;
    private ClientAuthentication clientAuthentication;

    private GenericOAuth2API() {
    }

    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return Optional.ofNullable(this.tokenExtractor).orElse(super.getAccessTokenExtractor());
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Optional.ofNullable(this.accessTokenVerb).orElse(super.getAccessTokenVerb());
    }

    @Override
    public String getRefreshTokenEndpoint() {
        return Optional.ofNullable(this.refreshTokenEndpoint).orElse(super.getRefreshTokenEndpoint());
    }

    @Override
    public String getRevokeTokenEndpoint() {
        return Optional.ofNullable(this.revokeTokenEndpoint).orElse(super.getRevokeTokenEndpoint());
    }

    @Override
    public BearerSignature getBearerSignature() {
        return Optional.ofNullable(this.bearerSignature).orElse(super.getBearerSignature());
    }

    @Override
    public ClientAuthentication getClientAuthentication() {
        return Optional.ofNullable(this.clientAuthentication).orElse(super.getClientAuthentication());
    }

    @Override
    public String getAccessTokenEndpoint() {
        return this.accessTokenEndpoint;
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return this.authorizationBaseUrl;
    }

    public static final class Builder {
        private String accessTokenEndpoint;
        private String refreshTokenEndpoint;
        private String revokeTokenEndpoint;
        private String authorizationBaseUrl;
        private TokenExtractor<OAuth2AccessToken> tokenExtractor;
        private BearerSignature bearerSignature;
        private Verb accessTokenVerb;
        private ClientAuthentication clientAuthentication;

        private Builder() {
        }

        public static Builder aGenericOAuth2API() {
            return new Builder();
        }

        public Builder withAccessTokenEndpoint(String accessTokenEndpoint) {
            this.accessTokenEndpoint = accessTokenEndpoint;
            return this;
        }

        public Builder withRefreshTokenEndpoint(String refreshTokenEndpoint) {
            this.refreshTokenEndpoint = refreshTokenEndpoint;
            return this;
        }

        public Builder withRevokeTokenEndpoint(String revokeTokenEndpoint) {
            this.revokeTokenEndpoint = revokeTokenEndpoint;
            return this;
        }

        public Builder withAuthorizationBaseUrl(String authorizationBaseUrl) {
            this.authorizationBaseUrl = authorizationBaseUrl;
            return this;
        }

        public Builder withTokenExtractor(TokenExtractor<OAuth2AccessToken> tokenExtractor) {
            this.tokenExtractor = tokenExtractor;
            return this;
        }

        public Builder withBearerSignature(BearerSignature bearerSignature) {
            this.bearerSignature = bearerSignature;
            return this;
        }

        public Builder withAccessTokenVerb(Verb accessTokenVerb) {
            this.accessTokenVerb = accessTokenVerb;
            return this;
        }

        public Builder withClientAuthentication(ClientAuthentication clientAuthentication) {
            this.clientAuthentication = clientAuthentication;
            return this;
        }

        public GenericOAuth2API build() {
            GenericOAuth2API genericOAuth2API = new GenericOAuth2API();
            genericOAuth2API.tokenExtractor = this.tokenExtractor;
            genericOAuth2API.bearerSignature = this.bearerSignature;
            genericOAuth2API.clientAuthentication = this.clientAuthentication;
            genericOAuth2API.revokeTokenEndpoint = this.revokeTokenEndpoint;
            genericOAuth2API.accessTokenVerb = this.accessTokenVerb;
            genericOAuth2API.accessTokenEndpoint = this.accessTokenEndpoint;
            genericOAuth2API.refreshTokenEndpoint = this.refreshTokenEndpoint;
            genericOAuth2API.authorizationBaseUrl = this.authorizationBaseUrl;
            return genericOAuth2API;
        }
    }
}

