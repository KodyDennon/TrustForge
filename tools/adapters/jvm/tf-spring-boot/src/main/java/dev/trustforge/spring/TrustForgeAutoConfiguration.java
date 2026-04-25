package dev.trustforge.spring;

import dev.trustforge.Client;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

@AutoConfiguration
@EnableConfigurationProperties(TrustForgeProperties.class)
@EnableAspectJAutoProxy
public class TrustForgeAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Client trustForgeClient(TrustForgeProperties props) {
        return new Client(props.getDaemonUrl());
    }

    @Bean
    @ConditionalOnProperty(prefix = "trustforge", name = "filter-enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<TrustForgeFilter> trustForgeFilterRegistration(Client client) {
        FilterRegistrationBean<TrustForgeFilter> reg = new FilterRegistrationBean<>(new TrustForgeFilter(client));
        reg.addUrlPatterns("/*");
        reg.setOrder(Integer.MIN_VALUE + 50);
        return reg;
    }

    @Bean
    @ConditionalOnMissingBean
    public TrustForgeAspect trustForgeAspect(Client client) {
        return new TrustForgeAspect(client);
    }
}
