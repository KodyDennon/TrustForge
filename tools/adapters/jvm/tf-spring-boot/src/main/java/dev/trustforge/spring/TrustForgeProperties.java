package dev.trustforge.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trustforge")
public class TrustForgeProperties {
    private String daemonUrl = "http://127.0.0.1:7878";
    private boolean filterEnabled = true;

    public String getDaemonUrl() { return daemonUrl; }
    public void setDaemonUrl(String daemonUrl) { this.daemonUrl = daemonUrl; }
    public boolean isFilterEnabled() { return filterEnabled; }
    public void setFilterEnabled(boolean filterEnabled) { this.filterEnabled = filterEnabled; }
}
