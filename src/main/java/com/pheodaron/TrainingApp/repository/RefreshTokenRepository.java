package com.pheodaron.TrainingApp.repository;

import com.pheodaron.TrainingApp.model.RefreshToken;
import com.pheodaron.TrainingApp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    RefreshToken findByToken(String token);

    @Modifying
    boolean existsByUser(User user);

    @Modifying
    boolean existsByToken(String token);

    @Transactional
    @Modifying
    int deleteByUser(User user);
}
