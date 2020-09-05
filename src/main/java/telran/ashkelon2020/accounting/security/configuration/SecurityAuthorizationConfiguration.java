package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {
	
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/account/register");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable(); // by default allows only GET requests. --> disable
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			
			.antMatchers(HttpMethod.POST, "/forum/post/{author}") // adddPost
				.access("#author==authentication.name and "
						+ "hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') and "
						+ "@customSecurity.checkExpdate(authentication.name)")
				
			.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}") // addComment
				.access("#author==authentication.name and "
						+ "hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') and "
						+ "@customSecurity.checkExpdate(authentication.name)")
			
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll() // findPostsByTags & findPostsByDate
			
			.antMatchers("/account/user/{login}/role/{role}**") // addRole & removeRole
				.hasRole("ADMINISTRATOR") 
				
			.antMatchers("/account/login**", "/forum/post/{id}/like**") // login & like
				.access("hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') and "
						+ "@customSecurity.checkExpdate(authentication.name)")
				
			.antMatchers(HttpMethod.PUT,"/account/user/{login}**") // updateUser
				.access("#login==authentication.name and "
						+ "hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') and "
						+ "@customSecurity.checkExpdate(authentication.name)") 
				
			.antMatchers(HttpMethod.DELETE, "/account/user/{login}**") // removeUser
				.access("#login==authentication.name")
				
			.antMatchers("/forum/post/{id}**") // updatePost & deletePost
				.access("(@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')) and "
						+ "hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER') and "
						+ "@customSecurity.checkExpdate(authentication.name)") 
				
			.antMatchers("/account/password**")
				.authenticated();
				
//			.anyRequest()
//				.authenticated();
		
	}

}
