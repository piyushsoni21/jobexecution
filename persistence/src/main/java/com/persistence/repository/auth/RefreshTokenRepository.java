package com.persistence.repository.auth;

import com.persistence.model.auth.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    @Query(value = """
      SELECT t.* FROM refresh_token t\s
      INNER JOIN base_user u ON t.user_id = u.id
      WHERE u.id = :id AND (t.expired = false OR t.revoked = false)
      """, nativeQuery = true)
    List<RefreshToken> findAllValidTokenByUser(@Param("id") Integer id);

    Optional<RefreshToken> findByToken(String token);
}
