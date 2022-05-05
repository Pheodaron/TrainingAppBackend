package com.pheodaron.TrainingApp.model;

import lombok.Data;

import javax.persistence.*;
import java.util.Date;

@Entity(name = "refreshtokens")
@Data
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;

    @Column(name = "token")
    private String token;

    @Column(name = "expiry_date")
    private Date expiryDate;
}
