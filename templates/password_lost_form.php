<?php

// Retrieve possible errors from request parameters
$attributes['errors'] = array();
if ( isset( $_REQUEST['errors'] ) ) {
    $error_codes = explode( ',', $_REQUEST['errors'] );

    foreach ( $error_codes as $error_code ) {
        $attributes['errors'] []= $this->get_error_message( $error_code );
    }
}

?>

<?php if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
        <p>
            <div class="warning_msg closable"><?php echo $error; ?></div>
        </p>
    <?php endforeach; ?>
<?php endif; ?>


<div id="password-lost-form" class="widecolumn">
    <?php if ( $attributes['show_title'] ) : ?>
        <h3><?php _e( 'Forgot Your Password?', 'intersynergy-login-plugin' ); ?></h3>
    <?php endif; ?>

    <p>
      <div class="information">
        <?php
            _e(
                "Enter your email address and we'll send you a link you can use to pick a new password.",
                'intersynergy-login-plugin'
            );
        ?>
      </div>
    </p>

    <form id="lostpasswordform" action="<?php echo wp_lostpassword_url(); ?>" method="post">
        <p class="form-row">
            <!-- <label for="user_login"><?php _e( 'Email', 'intersynergy-login-plugin' ); ?> -->
            <input type="text" name="user_login" id="user_login" placeholder="<?php _e( 'Email', 'intersynergy-login-plugin' ); ?>">
        </p>

        <p class="lostpassword-submit">
            <input type="submit" name="submit" class="lostpassword-button btn_large btn_theme_color btn_rounded btn_normal_style btn_full_width"
                   value="<?php _e( 'Reset Password', 'intersynergy-login-plugin' ); ?>"/>
        </p>
    </form>
</div>
