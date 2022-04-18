package be.vdab.beveiligd.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {
    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNIER = "magazijnier";
    private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public JdbcUserDetailsManager maakPrincipals() {
        return new JdbcUserDetailsManager(dataSource);
        //Je definieert met een JdbcUserDetailsManager bean dat een database de principals bevat. Je geeft de DataSource
        //mee die gebaseerd is op application.properties. Spring security zoekt de principals in de database die bij die
        //DataSource hoort.
    }
//Zonder Database kun je het in memory ook zo doen:

//    @Bean
//    public InMemoryUserDetailsManager maakPrincipals() {
////        Deze method geeft een InMemoryUserDetailsManager bean terug. Je maakt daarmee principals in het RAM geheugen.
////        Spring maakt dan zelf geen gebruiker met de naam user meer.
//        var joe = User.withUsername("joe")
//                .password("{noop}theboss")
//                .authorities(MANAGER)
//                .build();
//        //Je maakt een principal met de naam joe, het paswoord theboss en de authority manager. {noop} betekent dat het
//        //paswoord niet encrypted is.
//        var averell = User.withUsername("averall")
//                .password("{noop}hungry")
//                .authorities(HELPDESKMEDEWERKER, MAGAZIJNIER)
//                .build();
//        return new InMemoryUserDetailsManager(joe, averell);
//    }

    @Bean
    public WebSecurityCustomizer configureerWeb() {
        //Deze method geeft een WebSecurityCustomizer bean terug. Je configureert daarmee de web eigenschappen van de security.
        return (web -> web.ignoring().mvcMatchers("/images/**", "/css/**", "/js/**"));
        //Spring Security moet geen beveiliging doen op URL’s die passen bij /images/**. ** betekent dat het patroon ook subfolders van /images bevat.
    }

    @Bean
    public SecurityFilterChain geefrechten(HttpSecurity http) throws Exception {
        //Spring Security logt je uit bij een POST request naar de URL /logout. Toont dan standaard de inlogpagina als je
        // enkel http.logout() gebruikt. Hier redirecten we naar de welkompagina.
        http.logout(logout -> logout.logoutSuccessUrl("/"));
        //Deze method geeft een SecurityFilterChain bean terug. Je configureert daarmee toegangsrechten van de principals tot URL’s.
        http.formLogin(login -> login.loginPage("/login"));
        //De gebruiker authenticeert zich door zijn naam en paswoord te typen in een HTML form.
        http.authorizeRequests(requests -> requests
                //Enkel gebruikers met de authority manager hebben toegang tot URL’s die beginnen met /offertes.
                .mvcMatchers("/offertes/**").hasAuthority(MANAGER)
                //Enkel gebruikers met de authority magazijnier of helpdeskmedewerker hebben toegang tot URL’s die beginnen met /werknemers.
                .mvcMatchers("/werknemers/**").hasAnyAuthority(MAGAZIJNIER, HELPDESKMEDEWERKER)
                //Zo hebben alle gebruikers toegang tot de welkompagina en de loginpagina
                .mvcMatchers("/", "/login").permitAll()
                //Voor alle andere URL’s moet de gebruiker minstens ingelogd zijn.
                .mvcMatchers("/**").authenticated()

                //De volgorde waarmee je Matchers oproept is belangrijk: Spring Security overloopt ze in deze volgorde
                // - eerst de meest specifieke URLs (zonder wildcards)
                // - daarna de meer algemene URLs (met wildcards)
        );
        return http.build();
    }
}
