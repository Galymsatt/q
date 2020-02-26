package com.project.demo.controller;

import com.project.demo.entities.Comment;
import com.project.demo.entities.NewsPost;
import com.project.demo.entities.Role;
import com.project.demo.entities.Users;
import com.project.demo.repositories.CommentRepository;
import com.project.demo.repositories.NewsPostRepository;
import com.project.demo.repositories.RoleRepository;
import com.project.demo.repositories.UserRepository;
import com.project.demo.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.*;


@Controller
public class MainController {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserService userService;

    @Autowired
    NewsPostRepository newsPostRepository;

    @Autowired
    CommentRepository commentRepository;

    @GetMapping(value = "/auth_reg")
    public String auth_reg(){
        return "auth_reg";
    }

    @GetMapping(value = "/reg")
    public String reg(){
        return "registration";
    }

    @PostMapping(value = "/register")//Users registration
    public String register(@RequestParam(name = "email") String email,
                           @RequestParam(name = "password") String password,
                           @RequestParam(name = "re-password") String re_password,
                           @RequestParam(name = "name") String name,
                           @RequestParam(name = "surName") String surName){

        String redirect = "redirect:/auth_reg?registration_error";

        Users user = userRepository.findByEmailAndIsActiveIsTrue(email);
        if(user==null){

            Set<Role> roles = new HashSet<>();
            Role userRole = roleRepository.getOne(1l);
            roles.add(userRole);

            user = new Users(null, email, password, name, surName, true, roles);
            userService.registerUser(user);//osy zherge kelgen zat kaida ketedi?
            redirect = "redirect:/auth_reg?registration_success";

        }

        return redirect;
    }

    @GetMapping(value = "/profile")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String profile(ModelMap model){

        List<Users> allUsers = userRepository.findAll();
        model.addAttribute("allUsers", allUsers);

        Role moderator = roleRepository.getOne(3L);
        model.addAttribute("moderator", moderator);

        Role admin = roleRepository.getOne(2L);
        model.addAttribute("admin", admin);

        return "profile_admin";
    }
    @GetMapping(value = "/adminAdd")
    public String adminAdd(){
        return "admin_add";
    }

    @GetMapping(value = "/profile_moderator")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String profile_moderator(ModelMap model){

        List<Users> allUsers = userRepository.findAll();
        model.addAttribute("allUsers", allUsers);

        Role moderator = roleRepository.getOne(3L);
        model.addAttribute("moderator", moderator);

        Role admin = roleRepository.getOne(2L);
        model.addAttribute("admin", admin);

        return "profile_moderator";
    }

    @PostMapping(value = "/addUserModerator")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String addUserModerator(@RequestParam(name = "email") String email,
                                   @RequestParam(name = "password") String password,
                                   @RequestParam(name = "re-password") String re_password,
                                   @RequestParam(name = "name") String name,
                                   @RequestParam(name = "surName") String surName,
                                   @RequestParam(name = "USER", required = false, defaultValue = "1") int user_role,
                                   @RequestParam(name = "MODERATOR", required = false, defaultValue = "0") int moderator_role){

        String redirect = "redirect:/profile?user/moderator_added_error";

        Users user = userRepository.findByEmailAndIsActiveIsTrue(email);
        if(user==null){

            Set<Role> roles = new HashSet<>();
            roles.add(roleRepository.getOne(1l));
            if(moderator_role==1)
                roles.add(roleRepository.getOne(3L));

            user = new Users(null, email, password, name, surName, true, roles);
            userService.registerUser(user);//osy zherge kelgen zat kaida ketedi?
            redirect = "redirect:/profile?user/moderator_added_success";

        }

        return redirect;
    }

    @PostMapping(value = "/refPassword")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String refPassword(@RequestParam(name = "id") Long id,
                              @RequestParam(name = "password") String password){

        String redirect = "redirect:/profile?password_not_refreshed";

        Optional<Users> user = userRepository.findById(id);
        if(user.isPresent()){
            user.get().setPassword(password);
            userService.registerUser(user.get());
            redirect = "redirect:/profile?password_refreshed";
        }

        return redirect;
    }

    @PostMapping(value = "/blockUser")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MODERATOR')")
    public String blockUser(@RequestParam(name = "id") Long id){

        Optional<Users> user = userRepository.findById(id);
        if(user.isPresent()){
            user.get().setIsActive(false);
            userRepository.save(user.get());
        }


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            Users requester = userRepository.findByEmailAndIsActiveIsTrue(secUser.getUsername());
            if(requester.getRoles().contains(roleRepository.getOne(3L)))
                return "redirect:/profile_moderator";
        }


        return "redirect:/profile";
    }

    @PostMapping(value = "/unBlockUser")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MODERATOR')")
    public String unBlockUser(@RequestParam(name = "id") Long id){

        Optional<Users> user = userRepository.findById(id);
        if(user.isPresent()){
            user.get().setIsActive(true);
            userRepository.save(user.get());
        }


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            Users requester = userRepository.findByEmailAndIsActiveIsTrue(secUser.getUsername());
            if(requester.getRoles().contains(roleRepository.getOne(3L)))
                return "redirect:/profile_moderator";
        }

        return "redirect:/profile";
    }

    ///////////////////////////////END USER//////////////////////////////////////////

    //////////////////////NEWS POST///////////////////////////////////////////////////////

    @GetMapping(value = "/")
    public String index(ModelMap model){

        List<NewsPost> allNews = newsPostRepository.findAll();
        model.addAttribute("allNews", allNews);
        return "index";
    }

    @PostMapping(value = "/addPost")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String addPost(@RequestParam(name = "title") String title,
                          @RequestParam(name = "shortContent") String shortContent,
                          @RequestParam(name = "content") String content){

//        Users author = (Users) SecurityContextHolder.getContext().getAuthentication().getPrincipal();//berem avtorizovanny user, nuzno razobratsya kak eto pashet

        Users author = null;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            author = userRepository.findByEmailAndIsActiveIsTrue(secUser.getUsername());
        }

        newsPostRepository.save(new NewsPost(null, title, shortContent, content, author, new Date()));

        return "redirect:/";
    }

    @GetMapping(value = "/newsPage/{id}")
    public String newsPage(ModelMap model,
                           @PathVariable(name = "id") Long id){

        Optional<NewsPost> post = newsPostRepository.findById(id);
        model.addAttribute("post", post.orElse(new NewsPost(null, "No Name", "No Name", "No Name", null, null)));

        Role moderator = roleRepository.getOne(3L);
        model.addAttribute("moderator", moderator);

        Role user = roleRepository.getOne(1L);
        model.addAttribute("user", user);

        List<Comment> allComments = commentRepository.findByNewsPostId(id);
        model.addAttribute("allComments", allComments);

        Users adam = null;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            adam = userRepository.findByEmailAndIsActiveIsTrue(secUser.getUsername());
        }
        model.addAttribute("adam", adam);

        return "newsPage";
    }

    @PostMapping("/editPost")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String editPost(@RequestParam(name = "id") Long id,
                           @RequestParam(name = "title") String title,
                           @RequestParam(name = "shortContent") String shortContent,
                           @RequestParam(name = "content") String content){

        Optional<NewsPost> post = newsPostRepository.findById(id);
        if(post.isPresent()){
            post.get().setTitle(title);
            post.get().setShortContent(shortContent);
            post.get().setContent(content);

            newsPostRepository.save(post.get());
        }


        return "redirect:/newsPage/"+id;
    }


    @PostMapping("/deletePost")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String deletePost(@RequestParam(name = "id") Long id){

        Optional<NewsPost> post = newsPostRepository.findById(id);
        if(post.isPresent()){
            newsPostRepository.delete(post.get());
        }

        return "redirect:/";
    }

    /////////////////////////////////COMMENT//////////////////////////////////////////////////////////

    @PostMapping(value = "/addComment")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String addComment(@RequestParam(name = "postId") Long postId,
                             @RequestParam(name = "comment") String comment){

        Users author = null;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(!(authentication instanceof AnonymousAuthenticationToken)){
            User secUser = (User)authentication.getPrincipal();
            author = userRepository.findByEmailAndIsActiveIsTrue(secUser.getUsername());
        }



        commentRepository.save(new Comment(null, author, newsPostRepository.getOne(postId), comment, new Date()));

        return "redirect:/newsPage/"+postId;
    }


    @PostMapping(value = "/changeComment")
    public String changeComment(@RequestParam(name = "postId") Long postId,
                                @RequestParam(name = "comment_id") Long comment_id,
                                @RequestParam(name = "changedComment") String changedComment){

        Optional<Comment> comment = commentRepository.findById(comment_id);
        if(comment.isPresent()){
            comment.get().setComment(changedComment);
            commentRepository.save(comment.get());
        }

        return "redirect:/newsPage/"+postId;
    }

    @PostMapping(value = "/deleteComment")
    public String deleteComment(@RequestParam(name = "postId") Long postId,
                                @RequestParam(name = "comment_id") Long comment_id){

        commentRepository.delete(commentRepository.getOne(comment_id));

        return "redirect:/newsPage/"+postId;
    }
}
