<?php

// Retrieve recaptcha key
$attributes['recaptcha_site_key'] = get_option( 'intersynergy-login-recaptcha-site-key', null );

// Retrieve possible errors from request parameters
$attributes['errors'] = array();
if ( isset( $_REQUEST['register-errors'] ) ) {
    $error_codes = explode( ',', $_REQUEST['register-errors'] );

    foreach ( $error_codes as $error_code ) {
        $attributes['errors'] []= $this->get_error_message( $error_code );
    }
}

?>

<?php if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
      <div class="warning_msg closable"><?php echo $error; ?></div>
    <?php endforeach; ?>
<?php endif; ?>


<div id="register-form" class="widecolumn">
    <?php if ( $attributes['show_title'] ) : ?>
        <h3><?php _e( 'Register', 'intersynergy-login-plugin' ); ?></h3>
    <?php endif; ?>

    <form id="signupform" action="<?php echo wp_registration_url(); ?>" method="post">
        <p class="form-row">
            <!-- <label for="email"><?php _e( 'Email', 'intersynergy-login-plugin' ); ?><strong>*</strong></label> -->
            <input type="text" name="email" id="email" placeholder="<?php _e( 'Email', 'intersynergy-login-plugin' ); ?>">
        </p>

        <p class="form-row note-password">
          <?php _e( 'Note: Your password will be generated automatically and sent to your email address.', 'intersynergy-login-plugin' ); ?>
        </p>

<?php /*
        <p class="form-row">
            <!-- <label for="first_name"><?php _e( 'First name', 'intersynergy-login-plugin' ); ?></label> -->
            <input type="text" name="first_name" id="first-name" placeholder="<?php _e( 'First name', 'intersynergy-login-plugin' ); ?>">
        </p>

        <p class="form-row">
            <!-- <label for="last_name"><?php _e( 'Last name', 'intersynergy-login-plugin' ); ?></label> -->
            <input type="text" name="last_name" id="last-name" placeholder="<?php _e( 'Last name', 'intersynergy-login-plugin' ); ?>">
        </p>
*/ ?>
        <?php if ( $attributes['recaptcha_site_key'] ) : ?>
            <p class="form-row">
              <div class="recaptcha-container">
                  <div class="g-recaptcha" data-sitekey="<?php echo $attributes['recaptcha_site_key']; ?>"></div>
              </div>
            </p>
        <?php endif; ?>

        <p class="signup-submit">
            <input type="submit" name="submit" class="register-button button btn_large btn_theme_color btn_rounded btn_normal_style btn_full_width"
                   value="<?php _e( 'Register', 'intersynergy-login-plugin' ); ?>"/>
        </p>

        <p class="checkbox-list">
          <label for="terms">
            <input name="terms" type="checkbox" id="terms" value="agreed" checked>
            <?php
                printf(
                    __( 'Zapoznałem się z %s serwisu WP Doctor oraz akceptuję jego warunki.', 'intersynergy-login-plugin' ),
                    '<a href="'.home_url('dokumenty/regulamin').'" target="_blank">'.__( 'regulaminem', 'intersynergy-login-plugin' ).'</a>'
                );
            ?>
          </label>
        </p>
        <p class="checkbox-list">
          <label for="terms-data-operation">
            <input name="terms-data-operation" type="checkbox" id="terms-data-operation" value="agreed" checked>
            <span class="terms-data">
              <?php _e( 'Wyrażam zgodę na przetwarzanie moich danych osobowych przez Operatora', 'intersynergy-login-plugin' ) ?>
              <span class="terms-data-button"><?php _e('więcej...', 'intersynergy-login-plugin'); ?></span>
            </span>
            <span class="terms-data-more">
              <?php _e( 'Wyrażam zgodę na przetwarzanie moich danych osobowych przez Operatora w celu wykonywania zawieranej umowy, również w zakresie dokonywania płatności za usługę za pośrednictwem wyspecjalizowanych serwisów internetowych.', 'intersynergy-login-plugin' ) ?>
              <span class="terms-data-button-more"><?php _e('[mniej]', 'intersynergy-login-plugin'); ?></span>
            </span>
          </label>
        </p>
        <p class="checkbox-list">
          <label for="terms-data-marketing">
            <input name="terms-data-marketing" type="checkbox" id="terms-data-marketing" value="agreed" checked>
            <span class="terms-data">
              <?php _e( 'Wyrażam zgodę na otrzymywanie informacji handlowych pochodzących od Operatora' , 'intersynergy-login-plugin'); ?>
              <span class="terms-data-button"><?php _e('więcej...', 'intersynergy-login-plugin'); ?></span>
            </span>
            <span class="terms-data-more">
              <?php _e('Wyrażam zgodę na otrzymywanie informacji handlowych pochodzących od Operatora oraz jego partnerów w myśl treści art. 20 ust. 2 ustawy z dnia 18 lipca 2002 roku o świadczeniu usług drogą elektroniczną (Dz.U. z 2002 r., Nr 144, poz. 1204 ze zm.). Zgodnie z art. 24 ust. 1 pkt 3 i 4 ustawy z dnia 29 sierpnia 1997 r. o ochronie danych osobowych (tekst jedn. Dz.U. z 2002 r., Nr 101, poz. 926 z późn. zm.), podanie danych jest dobrowolne, a ponadto każdemu użytkownikowi przysługuje prawo dostępu do treści swoich danych oraz ich poprawiania.', 'intersynergy-login-plugin' ) ?>
              <span class="terms-data-button-more"><?php _e('[mniej]', 'intersynergy-login-plugin'); ?></span>
            </span>
          </label>
        </p>
        <script type="text/javascript">
          jQuery(document).ready(function($){
            $(".terms-data-button").click(function(event){
              event.preventDefault();
              $(this).parent().fadeOut(100, function(){
                $(this).parent().next('.terms-data-more').fadeIn('medium');
              }.bind(this));
            });
            $(".terms-data-button-more").click(function(event){
              event.preventDefault();
              $(this).parent().fadeOut();
              $(this).parent().prev('.terms-data').show();
            });
          });
        </script>



    </form>
</div>
