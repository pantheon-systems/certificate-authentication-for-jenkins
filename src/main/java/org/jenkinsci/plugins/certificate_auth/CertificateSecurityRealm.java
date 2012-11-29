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
import org.acegisecurity.GrantedAuthorityImpl;
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

/**
 * @author David Strauss
 * @author Kohsuke Kawaguchi
 */
public class CertificateSecurityRealm extends SecurityRealm {
    private final String userField;
    private final String groupField;

    @DataBoundConstructor
    public CertificateSecurityRealm(String userField, String groupField) {
        this.userField = userField;
        this.groupField = groupField;
    }

    /**
     * Field of the DN to look at.
     */
    public String getUserField() {
        return this.userField;
    }

    public String getGroupField() {
        return this.groupField;
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

                    final String dn = certChain[0].getSubjectDN().getName();

                    final String username = dn.split(getUserField() + "=")[1].split(",")[0];
                    final String group = dn.split(getGroupField() + "=")[1].split(",")[0];

                    GrantedAuthority[] authorities = new GrantedAuthority[] {
                            SecurityRealm.AUTHENTICATED_AUTHORITY,
                            new GrantedAuthorityImpl(group)
                		};

                    a = new UsernamePasswordAuthenticationToken(username, "", authorities);
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
