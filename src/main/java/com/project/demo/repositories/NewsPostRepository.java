package com.project.demo.repositories;

import com.project.demo.entities.NewsPost;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RequestParam;

@Repository
public interface NewsPostRepository extends JpaRepository<NewsPost, Long> {

}
