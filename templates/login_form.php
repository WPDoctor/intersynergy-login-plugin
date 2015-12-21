<?php

// Error messages
$errors = array();
if ( isset( $_REQUEST['login'] ) ) {
    $error_codes = explode( ',', $_REQUEST['login'] );

    foreach ( $error_codes as $code ) {
        $errors []= $this->get_error_message( $code );
    }
}
$attributes['errors'] = $errors;

?>

<!-- Show errors if there are any -->
<?php if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
      <div class="warning_msg closable"><?php echo $error; ?></div>
    <?php endforeach; ?>
<?php endif; ?>


<?php if ( $attributes['registered'] ) : ?>
    <p class="login-info">
      <div class="success closable">
        <?php
            printf(
                __( 'You have successfully registered to <strong>%s</strong>. We have emailed your password to the email address you entered.', 'intersynergy-login-plugin' ),
                get_bloginfo( 'name' )
            );
        ?>
      </div>
    </p>
<?php endif; ?>

<?php if ( $attributes['lost_password_sent'] ) : ?>
    <p class="login-info">
        <div class="information closable"><?php _e( 'Check your email for a link to reset your password.', 'intersynergy-login-plugin' ); ?></div>
    </p>
<?php endif; ?>

<?php if ( $attributes['password_updated'] ) : ?>
    <p class="login-info">
        <div class="success closable"><?php _e( 'Your password has been changed. You can sign in now.', 'intersynergy-login-plugin' ); ?></div>
    </p>
<?php endif; ?>

<!-- Show logged out message if user just logged out -->
<?php if ( $attributes['logged_out'] ) : ?>
    <p class="login-info">
        <div class="success closable"><?php _e( 'You have signed out. Would you like to sign in again?', 'intersynergy-login-plugin' ); ?></div>
    </p>
<?php endif; ?>

<div class="login-form-container">
    <?php if ( $attributes['show_title'] ) : ?>
        <h2><?php _e( 'Sign In', 'intersynergy-login-plugin' ); ?></h2>
    <?php endif; ?>

    <?php
        $args = array(
          'redirect' => admin_url(),
          'label_username' => __( 'Email', 'intersynergy-login-plugin' ),
          'label_password' => __( 'Password', 'intersynergy-login-plugin' ),
          'label_remember' => __( 'Remember Me', 'intersynergy-login-plugin' ),
          'label_log_in' => __( 'Sign In', 'intersynergy-login-plugin' ),
          'redirect' => $attributes['redirect'],
          'remember' => true,
          'value_remember' => true
        );
        // wp_login_form( $args );
    ?>
    <div class="login-form-container">
        <form method="post" action="<?php echo wp_login_url(); ?>">
            <p class="login-username">
                <!-- <label for="user_login"><?php _e( 'Email', 'intersynergy-login-plugin' ); ?></label> -->
                <input type="text" name="log" id="user_login" placeholder="<?php _e( 'Email', 'intersynergy-login-plugin' ); ?>">
            </p>
            <p class="login-password">
                <!-- <label for="user_pass"><?php _e( 'Password', 'intersynergy-login-plugin' ); ?></label> -->
                <input type="password" name="pwd" id="user_pass" placeholder="<?php _e( 'Password', 'intersynergy-login-plugin' ); ?>">
            </p>
            <p class="login-submit">
                <input type="submit" class="button btn_large btn_theme_color btn_rounded btn_normal_style btn_full_width" value="<?php _e( 'Sign In', 'intersynergy-login-plugin' ); ?>">
            </p>
            <p class="forgetmenot">
              <label for="rememberme">
                <input name="rememberme" type="checkbox" id="rememberme" value="forever"><?php _e( 'Remember me', 'intersynergy-login-plugin' ); ?></label>
            </p>
        </form>
    </div>

    <a class="forgot-password" href="<?php echo wp_lostpassword_url(); ?>">
        <?php _e( 'Forgot your password?', 'intersynergy-login-plugin' ); ?>
    </a>
</div>
