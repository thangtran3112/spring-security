package com.alibou.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Instead of providing RequestMatcher inside SecurityConfiguration
 * We can also annotate constroller directly with hasRole and hasAuthority
 * Must decorate SpringConfiguration class with @EnableMethodSecurity (Spring 3.x)
 * or @EnableGlobalMethodSecurity for Spring 2.x
 * Using @PreAuthorize annotation for more fine-grained control for each method
 */
@RestController
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin") // this is used for swagger to rename the section
//@SecurityRequirement(name = "bearerAuth") //in case if we want fine-grain access control to Swagger methods
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String get() {
        return "GET:: admin controller";
    }
    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    @Hidden  // Using Hidden to hide this API from Swagger Open API
    public String post() {
        return "POST:: admin controller";
    }
    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    @Hidden // Using Hidden to hide this API from Swagger Open API
    public String put() {
        return "PUT:: admin controller";
    }
    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    @Hidden // Using Hidden to hide this API from Swagger Open API
    public String delete() {
        return "DELETE:: admin controller";
    }
}
