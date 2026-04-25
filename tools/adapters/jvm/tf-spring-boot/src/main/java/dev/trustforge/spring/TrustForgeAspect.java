package dev.trustforge.spring;

import dev.trustforge.Client;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;

/** Method-level enforcement for {@link TrustForgeRequire}. */
@Aspect
public class TrustForgeAspect {

    private final Client client;

    public TrustForgeAspect(Client client) {
        this.client = client;
    }

    @Around("@annotation(dev.trustforge.spring.TrustForgeRequire) || @within(dev.trustforge.spring.TrustForgeRequire)")
    public Object around(ProceedingJoinPoint pjp) throws Throwable {
        MethodSignature sig = (MethodSignature) pjp.getSignature();
        TrustForgeRequire ann = sig.getMethod().getAnnotation(TrustForgeRequire.class);
        if (ann == null) {
            ann = pjp.getTarget().getClass().getAnnotation(TrustForgeRequire.class);
        }
        if (ann == null) return pjp.proceed();
        Client.Request r = new Client.Request().action(ann.value());
        if (!ann.resource().isEmpty()) r.resource(ann.resource());
        Client.Decision d = client.decide(r);
        if (!d.allow()) {
            throw new SecurityException("TrustForge denied: " + d.reason());
        }
        return pjp.proceed();
    }
}
