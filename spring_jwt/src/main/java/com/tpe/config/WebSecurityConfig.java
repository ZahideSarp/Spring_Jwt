package com.tpe.config;

import com.tpe.security.AuthTokenFilter;
import com.tpe.security.service.UserDetailsServiceImpl;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@AllArgsConstructor// anatasyonunu yazarsam @Autowired annt. yazmama gerek kalmıyor.Cunku eger class'ımın içerisinde
// tek const. varsa onu@Autowired ile annote etmeme gerek yoktu.Sadece kod okunurlugundan dolayı yazıyoruz.
//@AllArgsConstructor dedigimiz yere biz direk fieldlarımızı yazsakta o otomatikman burada ki fieldlardan
// bir const. olusturacagı için parametreli otomatikman const. injection olmuş oluyor.
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().
                sessionManagement().
                sessionCreationPolicy(SessionCreationPolicy.STATELESS). //Rest mimarı stateless oldugu için ben de bu yapının
                //stateless olmasını istiyorum demiş oluyorum
                // yani session kullanmayacgım diyorum
                and().
                authorizeRequests().//requestleri yetkilimi diye kontrol et
                antMatchers("/register", "/login").//bu enpointleri muaf tut
                permitAll().//
                anyRequest().authenticated();//bunlar dısında gelen tum endpoıntleri otantike et.

        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // !!! dun yazdigimiz kod blogunun kisa hali :
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }


}
