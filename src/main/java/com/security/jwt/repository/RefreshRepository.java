package com.security.jwt.repository;

import com.security.jwt.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity,Integer> {

    Boolean existsByRefresh(String refresh);

    @Transactional
    void deleteByRefresh(String refresh); // 이거도 실 프로젝트에서는 다르게 사용하던지
}
