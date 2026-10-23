# SecurityKid - Cybersecurity Blog

A modern, static blog website for cybersecurity enthusiasts, designed to be hosted on GitHub Pages.

## Features

- 🎨 Modern dark theme optimized for cybersecurity content
- 📱 Fully responsive design
- 🚀 Fast static site with no build process required
- 📝 Automatically fetches blog posts from Medium
- 🔗 Direct links to Medium articles
- 🔍 SEO-friendly structure
- 💻 Code syntax highlighting ready
- 🎯 Clean, professional design

## Getting Started

### 1. Fork or Clone This Repository

```bash
git clone https://github.com/yourusername/securitykid.git
cd securitykid
```

### 2. Customize Your Blog

#### Update Personal Information

Edit `index.html` and update:
- Blog name (currently "SecurityKid")
- About section content
- Contact links (GitHub, Twitter, Email)

#### Update Navigation

Modify the navigation links in `index.html` and `post.html` as needed.

### 3. Configure Medium Integration

The homepage reads `posts.json`, which is built from your Medium RSS feed. Browsers cannot call Medium directly, and the previous rss2json proxy now refuses the request.

Refresh the list from this folder:

```bash
python scripts/fetch_posts.py
```

A GitHub Action (`.github/workflows/refresh-posts.yml`) runs that command every day and can also be started by hand. After it commits `posts.json`, GitHub Pages serves the new list.

### 4. Deploy to GitHub Pages

1. Push your code to a GitHub repository
2. Go to repository Settings → Pages
3. Under "Source", select your branch (usually `main` or `master`)
4. Click Save
5. Your site will be available at `https://yourusername.github.io/repository-name/`

### 5. Custom Domain (Optional)

1. Add a `CNAME` file to the root with your domain name
2. Configure DNS settings as per GitHub Pages documentation
3. Update the domain in repository settings

## File Structure

```
securitykid/
├── index.html          # Main blog page
├── post.html           # Individual post page template
├── styles.css          # All styling
├── script.js           # Blog functionality and posts data
├── README.md           # This file
└── .nojekyll           # Disables Jekyll processing (if needed)
```

## Customization

### Colors

Edit the CSS variables in `styles.css`:

```css
:root {
    --bg-primary: #0a0e27;
    --bg-secondary: #141b2d;
    --accent-primary: #3b82f6;
    /* ... more variables */
}
```

### Fonts

The blog uses:
- **Inter** for body text
- **JetBrains Mono** for code

Change fonts in the `<head>` section of `index.html` and `post.html`.

### Logo

Replace the emoji logo (🔒) in `index.html` with your own logo image or text.

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Contributing

Feel free to fork this project and customize it for your own use. If you make improvements that could benefit others, pull requests are welcome!

## License

This project is open source and available under the MIT License.

## Credits

- Design inspired by modern cybersecurity and developer blogs
- Fonts provided by Google Fonts
- Icons: Emoji-based (can be replaced with icon fonts or SVGs)

## Support

For issues or questions:
- Open an issue on GitHub
- Check the documentation
- Review the code comments

---

**Happy Blogging! 🔒**

