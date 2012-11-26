/*
 * The MIT License
 *
 * Copyright (c) 2011, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.certificate_auth;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import java.security.cert.X509Certificate;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author David Strauss
 * @author Kohsuke Kawaguchi
 */
public class CertificateSecurityRealm extends SecurityRealm {
    private final String dnField;
    private final ArrayList<String> useSecondaryDnOn;
    private final String secondaryDnField;

    @DataBoundConstructor
    public CertificateSecurityRealm(String dnField, String[] useSecondaryDnOn, String secondaryDnField) {
        this.dnField = dnField;
        this.useSecondaryDnOn = new ArrayList<String>(this.useSecondaryDnOn);
        this.secondaryDnField = secondaryDnField;
    }

    /**
     * Field of the DN to look at.
     */
    public String getDnField() {
        return dnField;
    }

    public ArrayList<String> getUseSecondaryDnOn() {
        return useSecondaryDnOn;
    }

    public String getSecondaryDnField() {
        return secondaryDnField;
    }

    @Override
    public boolean canLogOut() {
        return false;
    }

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new Filter() {
            public void init(FilterConfig filterConfig) throws ServletException {
            }

            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                HttpServletRequest r = (HttpServletRequest) request;
                final X509Certificate[] certChain = (X509Certificate[])
                  request.getAttribute("javax.servlet.request.X509Certificate");

                Authentication a;
                if (certChain == null || certChain[0] == null) {
                    a = Hudson.ANONYMOUS;
                } else {
                    //final String issuer = certChain[0].getIssuerX500Principal().getName();
                    //final String subject = certChain[0].getSubjectX500Principal().getName();
                    final String dn = certChain[0].getSubjectDN().getName();
                    String group = dn.split(getDnField() + "=")[1].split(",")[0];
                    String uid;
                    if (getUseSecondaryDnOn() != null && getUseSecondaryDnOn().contains(group)) {
                    String username = dn.split(getSecondaryDnField() + "=")[1].split(",")[0];
                        uid = username;
                    } else {
                        uid = group;
                    }
                    a = new UsernamePasswordAuthenticationToken(uid,"",new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY});
                }

                SecurityContextHolder.getContext().setAuthentication(a);

                chain.doFilter(request,response);
            }

            public void destroy() {
            }
        };
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) {
                return authentication;
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                throw new UsernameNotFoundException(username);
            }
        });
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return Messages.CertificateSecurityRealm_DisplayName();
        }
    }
}
