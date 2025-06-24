package com.sharifrahim.jwt_auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "api_client")
@Getter
@Setter
@NoArgsConstructor
public class ApiClient extends Auditable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "client_secret_enc", nullable = false)
    private String clientSecretEnc;

    @Column(name = "private_key_enc", nullable = false)
    private String privateKeyEnc;

    @Column(name = "username")
    private String username;

    @Column(name = "full_name")
    private String fullName;

    @Column(name = "company_name")
    private String companyName;

    @Column(name = "registration_no")
    private String registrationNo;
}
